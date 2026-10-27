# Production readiness ledger

One status per readiness gate, with the evidence behind it. It answers "what has actually been shown to work, and how", not "what is designed". It complements two existing records and does not replace them:

- the **deferred-issue ledger** in `docs/P-ROADMAP.md`, which holds every open finding (cited below as "ledger row" with its line number at `be5cc23`; numbers shift as rows are added);
- `docs/RELEASE-READINESS.md`, which holds the AI release gates and the D1-D14 rehearsals.

SaaS OS is a library that products pin by commit SHA and deploy. A gate below concerns what this repository ships and tests; deploying, operating and monitoring a product is the product's job, and evidence that needs a live deployment is marked **blocked**.

**Statuses.** *Verified*: an automated test or a required CI check exercises the property, and the tests are named. *Partially verified*: some of it is exercised, the rest is named as a gap. *Untested*: nothing exercises it. *Blocked*: it needs an action outside this repository (a deployment, a provider, an owner decision). Documentation alone never makes a gate verified, and a green CI run does not make SaaS OS production-ready.

**Required checks.** The `main` ruleset (25485150) requires seven CI checks on the exact head before a merge: `backend checks`, `frontend checks`, `security checks`, `docker build + runtime validation`, `packaging gate (wheel contents + isolated install)`, `migration gate (P1.7)` and `security integration gate (PRIV-03 RA-11-F1)`. Integration tests (`-m integration`) run only in the last one, through `scripts/check-integration.sh`, which fails if no test ran or any test was skipped.

**Last reviewed:** 2026-10-27, at `main` `be5cc23`. Re-review a gate whenever a change touches its evidence.

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

**Overall: not production-ready.** No gate is failing, but most are only partially verified, and several depend on actions outside the repository: a live deployment, live provider checks, and owner decisions on worker egress and on the external audit store. On 2026-10-27 the deferred-issue ledger had no open CRITICAL row; two HIGH rows (1011, 1012, ZITADEL advisories) fixed in the repository and open only for a deployment that has not upgraded; and five open MEDIUM rows (863, 891, 892, 905, 1016).

## 1. Architecture and public package interfaces — partially verified

- Layer and import contracts: `lint-imports` (contracts in `pyproject.toml`, `[tool.importlinter]`) runs in `backend checks` through `scripts/check-backend.sh`; `tests/architecture/test_layer_boundaries.py`, `tests/architecture/test_namespace_contract.py`.
- Package layout: `tests/test_wheel_contents.py` (top-level import names, isolated non-editable install) in the packaging gate.
- Public surfaces pinned module by module, not as a whole: `tests/infra/test_db_public_surface_unit.py`, `tests/infra/jobs/test_public_api.py`, `tests/architecture/test_platform_authority_contract.py`, `tests/architecture/test_ai_inference_boundaries.py`.
- Gaps: no test of the whole public API; products import the internal `control_plane.orchestration.tools` (ledger row 966); the `api/` split and the classification of `tenant_status.py` are undecided (872, 873); `docs/API-ARCHITECTURE.md` contradicts Core owning no HTTP surface (889).

## 2. Authentication and authorization — partially verified

- OIDC and sessions: `tests/core/identity/test_oidc.py`, `test_oidc_flow_unit.py`, `test_sessions_unit.py`; `tests/api/auth/test_auth_flow_integration.py`, `test_proxy_trust_integration.py`; CSRF `tests/api/test_csrf_unit.py`.
- API keys: `tests/core/api_keys/` (isolation, revocation, a revoked key is not rotated), `tests/api/v1/test_api_key_request_auth_integration.py`, `tests/api/test_credential_failure_limit_integration.py`.
- RBAC and platform authority, including negative controls and forced races: `tests/core/rbac/test_authorization_integration.py`, `test_deny_authorization_integration.py`, `test_authorization_transaction_race_integration.py`; `tests/core/platform_authority/test_platform_authority_negative_controls_integration.py`, `test_user_deactivation_race_integration.py`.
- Invitation acceptance: `tests/core/identity/test_invitation_integration.py`, run in full by the integration gate since pull request #119 (eleven of its tests had been deselected since 2026-09-19).
- Gaps: no live identity provider in CI (`test_live_zitadel_integration.py` is excluded by design); ZITADEL v4.19.5 only partly verified live (ledger row 1016, MEDIUM); invitation acceptance reads the verified email from the ID token only (1008); design residuals (948, 950, 956, 957).

## 3. Tenant isolation and database security — verified

- Schema sweep against the isolation registry, as the restricted application role: `tests/infra/db/test_rls_coverage_sweep_integration.py` (`test_every_tenant_owned_table_has_forced_rls_and_exactly_the_canonical_policy`, `test_no_security_definer_function_exists_in_saas_os_schemas`).
- `tests/infra/db/test_rls.py`, `test_role_guard_integration.py`, `test_tenant_session_scope_validation.py`; the `*_isolation_integration.py` modules (for example `tests/core/tenancy/test_tenant_isolation_integration.py`, `tests/core/rbac/test_rbac_isolation_integration.py`); `tests/architecture/test_tenant_session_boundary.py`.
- Run on real PostgreSQL 16 in the integration gate, with the application and platform-configuration roles created by `saas_os/infra/db/init/`.
- Limitations: concurrent deny grants in unrelated tenants can deadlock, and PostgreSQL aborts one (fails closed; ledger row 913); the external append-only audit copy is a deployment step (905, gate 5).

## 4. API and outbound-network security — partially verified

- Webhook SSRF and egress: `tests/core/webhooks/test_webhook_ssrf_policy_unit.py`, `test_webhook_allowed_ports_unit.py`, `test_webhook_shared_egress_unit.py`; `tests/infra/egress/test_strict_egress_unit.py`, `test_strict_egress_socket_unit.py`.
- Rate limiting: `tests/infra/ratelimit/test_ratelimit_atomicity_integration.py`, `test_ratelimit_backend_failure_integration.py`, `tests/api/v1/test_ratelimit_failure_integration.py`.
- Edge: `tests/architecture/test_single_origin_edge.py` against a real Caddy in `backend checks`; CORS `tests/api/test_cors_unit.py`.
- Gaps: worker egress in the production topology is untested and undecided (ledger rows 891, 892, MEDIUM; 894); AI egress limits are provisional (963); `scripts/check-single-origin.sh` is not a CI check; payment-page refusals have no rate limit of their own (880); `httpx` logs a request line the egress client's docstring says it never writes (902).

## 5. Data protection and secret management — partially verified

- Secret scan: `scripts/check-security.sh` in `security checks`; `tests/architecture/test_secrets_gate.py`, `test_security_script_reporting.py` (UTF-8 mode on Windows since pull request #114).
- No credential reaches a value's representation or a built image, per `tests/infra/secrets/test_secret_value_safety.py` and `test_no_secrets_in_docker_artifacts.py`; log redaction `tests/infra/observability/test_logging_redaction_unit.py`, `test_redaction_unit.py`.
- Transport encryption at configuration level (ADR-0021): `tests/infra/db/test_tls_requirement_unit.py`, `tests/infra/jobs/test_redis_tls_client_defaults_unit.py`.
- Retention, purge and erasure: `tests/core/tenancy/test_retention_classification.py`, `test_tenant_purge_integration.py`, `test_purge_participants_integration.py`, `tests/core/identity/test_erasure_integration.py`; backup encryption `tests/infra/db/test_backup_encryption_unit.py`.
- Gaps: encryption in transit is not exercised end to end in CI (`scripts/check-docker-prod-tls.sh` is a manual run; ledger row 1019); the external audit store is not deployed (905, blocked); Core cannot detect a missing purge participant (1025, 1026); AI tables keep the `DEFERRED_POLICY` retention class (1004); redaction does not cover values interpolated into a log message string (recorded by `test_message_string_interpolation_is_an_explicitly_uncovered_path`). Webhook URLs are kept out of `httpx`'s request line by `configure_logging()` since pull request #122, but a product configuring logging another way can bring it back; the OIDC callback's `code` and `state` reach uvicorn's access log (both assessed 2026-10-27, LOW, in the deferred-issue ledger next to the #122 row).

## 6. Background-job reliability and recovery — partially verified

- Real worker process: `tests/api/test_worker_runtime_integration.py` (retry then dead-letter, clean SIGTERM, refusal to start without Redis).
- Outbox: `tests/api/test_outbox_dispatcher_integration.py` (a worker that dies after the consumer ran lets the event run again; an event with no consumer is dead-lettered), `tests/api/test_outbox_consumer_idempotency_integration.py` (concurrent executions count once; an email is not resent once completed).
- `tests/infra/jobs/test_dead_letter.py`, `test_queue_retry.py`, `test_redis_persistence_integration.py`; `tests/core/test_job_lifecycle_fencing_integration.py`.
- Gaps: no test replays dead-lettered jobs; Redis has no persistence in the development Compose file (ledger row 875); Resend `Retry-After` is not read (895).

## 7. Payment and email integrations — partially verified; live providers blocked

- Stripe webhook authenticity, replay and duplicates: `tests/core/billing/test_billing_unit.py` (tampered payload, wrong secret), `test_stripe_event_parsing_unit.py`, `tests/api/v1/test_billing_events_router_integration.py` (`test_a_stale_delivery_is_refused`), `tests/core/billing/test_provider_events_integration.py` (duplicate and concurrent deliveries recorded once), `test_billing_security_attacks_integration.py`, `test_billing_projections_integration.py`.
- Email with mock transports and fakes only: `tests/core/email/test_resend_provider_unit.py`, `test_smtp_provider_unit.py`, `test_email_provider_selection_unit.py`, `tests/core/notifications/test_email_channel_integration.py`.
- Blocked: Stripe test mode (`tests/core/billing/test_billing_stripe_integration.py`) and live Resend are outside CI, which holds no provider credential (ADR-0012). Resend has been checked live once, partly (ledger rows 893, 897); Stripe subscriptions created before ADR-0052 may lack `save_default_payment_method` (925, an operator check).
- Gaps: the production worker cannot reach SMTP or the internet (891, 892, MEDIUM).

## 8. Dependency and supply-chain security — partially verified

- `security checks`: `pip-audit` over the resolved environment, `scripts/npm_audit_gate.py` (high and critical, exceptions in `scripts/security-exceptions.json`, currently none), detect-secrets. The gate's own logic is tested: `tests/architecture/test_npm_audit_gate.py`, `test_security_script_reporting.py`, `test_ci_hermeticity.py`.
- `frontend/package-lock.json` is committed; `detect-secrets` and `ruff` are pinned exactly.
- Gaps: no Python lock or constraints file, only lower bounds in `pyproject.toml` (ledger row 928, owner decision); base images (`python:3.13-slim`, `node:22-slim`) are pinned by tag, not by digest (row added 2026-10-27; the Actions in both workflows are pinned by commit SHA since pull request #121, enforced by `tests/architecture/test_ci_workflow_pins.py` and `test_release_script.py`); no SBOM or image scan; the release workflow's approval reviewer and tag signing are not in place (1010).

## 9. Unit, integration, migration, packaging and runtime testing — partially verified

- The seven required checks, each a script: `check-backend.sh`, `check-frontend.sh`, `check-security.sh`, `check-docker.sh`, `check-packaging.sh`, `check-migrations.sh`, `check-integration.sh`.
- Intermittent checks found and fixed on 2026-10-27: the worker dead-letter test (pull request #115) and the Docker readiness check (pull request #117).
- Gaps: by design, live Stripe, ZITADEL, GitHub and AI-provider tests are not in CI; `check-docker-prod.sh` and `check-docker-prod-tls.sh` (the production topology) are manual runs; narrow pytest selections can shadow `control_plane` (ledger row 886).

## 10. Observability, health checks and alerting — partially verified; alerting untested

- Health: `tests/api/test_health_unit.py`, `tests/infra/health/test_health_integration.py`, `test_readiness_aggregate.py`, `test_readiness_db.py`, `test_readiness_redis.py`; `check-docker.sh` asserts `/healthz` and `/readyz`, including `503` with no connection detail when PostgreSQL is down.
- Logging and tracing: `tests/infra/observability/test_end_to_end.py`, `test_otel.py`, `tests/api/test_middleware_correlation_bound_unit.py`.
- Untested: the repository has no metrics exporter and no alerting; the observability backend is undecided (ledger row 874, ADR-0009); the audit digest's missing-record alert and scheduled verification are a deployment step (905). `tests/core/audit_digest/test_audit_digest_integration.py` covers the offline verification only.

## 11. Backup restoration and disaster recovery — partially verified; off-host recovery blocked

- `tests/infra/db/test_backup_restore_drill_integration.py`: `test_full_disaster_recovery_drill` (back up, drop, restore, then RLS, isolation and roles re-checked), the extended pipeline with `age` encryption and an off-site copy run twice from clean environments, and the checksum, corrupt-archive and existing-target refusals.
- `tests/infra/db/test_zitadel_backup_restore_drill_integration.py`, `test_backup_offsite_fail_closed_unit.py`, `tests/infra/jobs/test_redis_persistence_integration.py`.
- Blocked: no restore on separate infrastructure or real off-host storage (`docs/RELEASE-READINESS.md`, D13); the systemd timers in `deploy/` have never run as units; the external audit store (905).

## 12. Deployment, rollback, configuration validation, environment separation — partially verified; deployment blocked

- Migrations and their order: the migration gate (`tests/infra/db/test_migration_gate_integration.py`, `tests/test_reference_consumer_integration.py`, the `tests/infra/db/test_*_migration_rollback.py` files).
- Fail-closed configuration: `tests/infra/secrets/test_config_selection.py` (an unset `ENVIRONMENT` refuses), `tests/core/test_config.py`, `tests/api/auth/test_auth_config_unit.py`, `tests/infra/jobs/test_jobs_config.py`.
- Production topology checked statically: `tests/architecture/test_production_identity_topology.py`, `test_email_provider_topology.py`, `test_single_origin_edge.py`.
- Blocked: no product deployment, or rollback of one, has been exercised (D14 is local only); the production-stack scripts are not CI checks; worker egress (891, 892).

## 13. Operational runbooks and incident response — partially verified

- Exercised: the operator CLI (`tests/core/platform_authority/test_operator_cli_integration.py`, `tests/ops/test_operator_cli_unit.py`), platform bootstrap and break-glass recovery (`tests/api/test_platform_bootstrap_integration.py`, `tests/core/platform_authority/test_last_owner_recovery_concurrency_integration.py`), first-tenant bootstrap (`tests/api/test_tenant_bootstrap_integration.py`), audit digest verification.
- Written but not rehearsed (`docs/RUNBOOKS.md`): ZITADEL restart, upgrade, master-key recovery and compromise; Login V2 cookie-secret rotation; restoring or cloning a database; the external PostgreSQL and Redis checklist.

## 14. Consumer-package compatibility and upgrade procedures — partially verified

- `tests/test_wheel_contents.py` (isolated install, every migration revision in the wheel, provider extras), `tests/test_consumer_pins_unit.py` (exact 40-character SHA pins), the reference-consumer integration and scenario tests, `tests/test_consumer_scaffold_integration.py`.
- Upgrade notes: `docs/CONSUMER-GUIDE.md` section 14 and `CHANGELOG.md`.
- Gaps: CI tests the examples against the working tree, not against the commit they pin, and that pin lacks `register_purge_participant()`, which their code calls (ledger row 1027); versioning and support-window policy undecided (869, 870, 871, 928).

## 15. Documentation and known limitations — partially verified

- `docs/ADR/README.md` indexes ADRs 0001-0058; the deferred-issue ledger records findings with their evidence and is updated by each fix.
- Gaps: nothing checks the documents for staleness; known stale statements include `docs/RELEASE-READINESS.md` naming ZITADEL 4.19.0 for the TLS validation, ADR-0035's NAT64 statement (ledger row 967) and `docs/API-ARCHITECTURE.md` (889).
