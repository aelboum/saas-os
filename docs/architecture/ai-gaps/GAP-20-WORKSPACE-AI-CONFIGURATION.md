# Gap 20: Tenant AI enablement and model selection: options and recommendation

**Status: Proposal. This document changes no code, test, public contract, migration or ADR.** Proposal submission is not implementation approval.
Written 2026-11-09 on `main` at `0f9bf4d` (v0.10.0, Alembic head `e2b7c4d9a1f6`).
Facts below carry a `file:line` citation and were read from code; a statement with no citation is an inference. Items marked *not verified* were not run or not read in full.

**Vocabulary.** The request says "workspace". SaaS-OS calls the isolation unit a **tenant** and keeps "workspace" out of Core (`docs/architecture/PLATFORM_BOUNDARIES.md`). In this document "workspace" means "tenant". A product may call its tenants workspaces.

**Scope.** Text-based AI only. Voice, telephony, speech-to-text, text-to-speech and real-time voice agents are out of scope and remain a separate future capability (issue #206 is the only voice-adjacent item).

## 1. What is requested and what it unblocks

A shared platform capability, not a product feature. An authorized administrator of a tenant can: turn AI on or off; choose an approved provider and model from the central catalogue; see which models the tenant may use; change the model without product code changes; configure or inherit restrictions; and have AI stop immediately on a security, contractual or spending issue. Products such as LeadStack consume it and must not build their own provider management.

It unblocks Gap 21 (the budget needs a selected model to price) and Gap 22 (the usage view needs the settings it reports on).

## 2. Existing-state audit (what SaaS-OS already does)

Most of the control exists as a Python service layer. What is missing is mostly the read side, a platform-side hold, one validation and the exposed API.

**Provider abstraction and adapters.**
- One abstraction: `saas_os/control_plane/inference/adapters/base.py` (stateless adapters, no retries, no policy or secret reads, `EgressClient` plus `OpaqueCredential`). Adapters: OpenAI-compatible, Anthropic Messages, Gemini generateContent (registered by default, `service.py:263-274`), and a test-only `FakeAdapter`.
- Protocol enum has three values: `config/models.py:39-42`.

**Catalogue.** DB-backed, global, platform-managed, no tenant id and no RLS (`config/models.py:1-10`): `ai_providers` (key, protocol, base_url, credential_ref, credential_origin, status, `data_handling` JSON with `residency`, `retention_days`, `training_use`), `ai_models` (capabilities, limits, lifecycle active/deprecated/disabled, `retire_after`), `ai_aliases` (alias to ordered candidate list), `ai_endpoint_trust`, `ai_destination_policy` (provider and classification allowed), `ai_model_prices`. Residency, retention and training are **per provider** and are operator declarations, not verified facts (`config/service.py:453-499`). There are no per-model data-handling fields.

**Per-tenant enablement.** Exists. `ai_tenant_policies.enabled` (`models.py:159-170`), set by `set_tenant_ai_policy` (`config/tenant_policy.py:169-189`). **Default is disabled**: no row is created at tenant creation, and `load_tenant_ai_policy` returns `exists=False, enabled=False` without a row (`tenant_policy.py:400-404`). `evaluate` raises `InferencePolicyDeniedError("tenant_policy_absent_or_disabled")` (`resolution.py:409-410`). A second default-off layer is the plan entitlement `ai.inference`, which fails closed on anything but literal `True` (`admission.py:98-108`) and is checked before a concurrency slot is taken (`service.py:730-748`).

**Per-tenant model selection.** Exists as an **allowlist, not a choice**. A tenant grants specific (provider, model) pairs per use case and classification with `grant_destination` (`tenant_policy.py:252-311`). The product requests an **alias**, and the platform-defined alias fixes candidate order. The tenant narrows the set; it cannot pick or order models.

**Tenant preferences.** `ai_tenant_preferences` holds `allowed_residency`, `max_retention_days`, `exclude_training_use`; they can only narrow eligibility (`models.py:208-224`, `resolution.py:333-350`). Undeclared provider data handling fails every requirement.

**Selection-time checks** (`resolution.py:398-449`, called from `_begin_attempt`, `service.py:404`, before any content is sent): tenant policy present and enabled; use-case grant covers the classification; provider active and credential bound; model not disabled or past `retire_after`; installation destination policy allows it; tenant destination grant covers it; ADR-0013 evaluator allows it; capabilities satisfied; tenant preferences met. A policy-violating model is therefore never *used*.

**Authorization and audit.** Every write requires tenant permission `ai.policy:manage`; reads `ai.policy:read` (`inference/permissions.py:25-30`; `tenant_policy.py:144, 441-448`). Only `UserCaller` and `ServiceAccountCaller`; system callers are refused (`tenant_policy.py:133-134`). Support access can never satisfy `ai.policy:manage`, `ai.inference:run` or `ai.credential:manage` (`core/rbac/authorization.py:330-335`). Success writes a tenant audit row in the same transaction (`tenant_policy.py:148-156`); refusal writes a `denied` row after rollback (`:103-119, 158-160`). Actions: `ai.policy.set`, `ai.policy.grant_use_case`, `ai.policy.grant_destination`, `ai.policy.set_preferences`. The three policy tables have tenant RLS (`e4b8c2d6f1a3`, `b8e2d4f6a1c3`). The product must register the permissions with `register_ai_permissions()` and bind them to a role; nothing in `saas_os` calls it and no role grants them by default.

**Secrets.** Only a secret *name* is stored (`AIProvider.credential_ref`, `models.py:81`); the name must be in the deployment allowlist `AI_PROVIDER_CREDENTIALS` and is re-checked on every call; the value comes from the secrets provider; the credential is bound to the endpoint origin (`credentials.py:40-92`). `OpaqueCredential.__repr__` is redacted (`adapters/base.py:57-72`). All tenants share the platform's provider credentials; tenant-owned credentials are **not implemented** (`ai.credential:manage` is declared but unused; ADR-0054 and the AI roadmap record an owner decision as pending).

**Outbound controls.** Adapters use `StrictEgressClient` with `allowed_ports={provider port}` and the trusted-endpoint table (`service.py:225-234`); timeouts and response cap in `egress_config.py:69-88`.

**Kill switches that exist.** Tenant: `set_tenant_ai_policy(enabled=False)`, a grant with `enabled=False`, or removing the `ai.inference` entitlement; all take effect for new requests. Platform: `set_provider_status('disabled')` (`config/service.py:428`) and `set_model_lifecycle(..., 'disabled')` (`:570`). In-flight streams are not cut (`AI-INFERENCE-CONTRACTS.md:328`; streaming is disabled anyway).

**Surfaces.** There is **no HTTP route** for any AI function (`ops/ai_commands.py:2-3`), and an import-linter test forbids the HTTP layer from importing `saas_os.inference` (`tests/architecture/test_ai_inference_boundaries.py`). The platform CLI has 13 `ai-*` commands but none sets tenant policy (`ai_commands.py:30-31`).

**Tests that pin today's behaviour:** `tests/control_plane/inference/test_ai_tenant_preferences_integration.py`, `test_ai_configuration_integration.py`, `test_ai_inference_integration.py`, `test_ai_inference_governance_unit.py`, `test_ai_credentials_unit.py`, `tests/infra/db/test_ai_inference_configuration_migration.py`, `tests/architecture/test_ai_inference_boundaries.py`.

**Hierarchy.** Tenants form a single-parent tree (`core/tenancy/models.py:18-41`); a parent gains no automatic access to a child. The inference package has no parent or inheritance logic. No agency concept exists.

## 3. Problem statement: what is genuinely missing

| # | Gap | Evidence |
|---|---|---|
| G20-1 | No tenant-facing read of "which models may this tenant use, and why not". `read_tenant_ai_policy` returns only the tenant's own grants; `read_ai_configuration` is platform-only. | `tenant_policy.py:441-448`; `platform.ai_config:read` |
| G20-2 | The tenant cannot choose or reorder the model. Order is the platform alias's. | `resolution.py` candidate order |
| G20-3 | `grant_destination` accepts a model the tenant's own preferences or the installation policy would exclude. The model is never used, but a settings screen would show it as granted. | Section 2, selection checks |
| G20-4 | No platform-side per-tenant AI hold. A platform operator can disable a provider or model for everyone, but cannot suspend one tenant's AI for a security or contractual reason, because no platform permission can write tenant policy. | `tenant_policy.py`; Section 2 |
| G20-5 | No exposed API (HTTP or otherwise stable for a settings UI) for tenant AI settings. | Section 2, Surfaces |
| G20-6 | No default role binding for `ai.policy:*`. | `permissions.py:33-35` |
| G20-7 | "Inherit restrictions" has no parent-to-child mechanism. Only installation-wide policy applies to all tenants. | `core/tenancy/models.py:21-24` |

## 4. Options

**Option A (recommended): extend the existing tenant policy; no second mechanism.**
1. *Eligibility read.* New service function `list_eligible_models(caller, tenant_id, *, use_case=None)` returning one `EligibleModelView` per catalogue model: provider key, model id, lifecycle, capabilities, declared `data_handling` (as declared), `granted: bool`, `eligible: bool`, and `blocked_by`, a closed set of reason codes (`provider_disabled`, `credential_unbound`, `model_disabled`, `model_retired`, `destination_policy_denied`, `residency`, `retention`, `training_use`, `capability`, `not_granted`). It reuses `resolution.evaluate` pieces and adds no policy logic. It never returns `credential_ref`, `base_url` or secrets (`credential_bound: bool` only). Requires `ai.policy:read`.
2. *Selection.* A nullable `preference_rank` on `ai_tenant_destination_grants`. The effective candidate order is the alias candidates the tenant has granted, ranked by `preference_rank` then alias order. A tenant can never add a model outside the alias, so the platform keeps control of what an alias may reach. `null` everywhere equals today's behaviour. The product keeps requesting an alias and needs no code change when the tenant re-ranks.
3. *Grant-time validation.* `grant_destination` and `set_preferences` refuse (new reason code) a grant the evaluator would never allow, and report the reason code. Existing grants are untouched and still re-evaluated at call time, which stays the authority.
4. *Platform hold.* New platform-owned table `control_plane.ai_tenant_holds` (tenant id, reason code from a closed set `security`, `contractual`, `spending`, `operator`, `held_at`, `held_by` platform subject, `released_at`). Checked in `load_snapshot` before the tenant policy, so a held tenant fails closed with `InferencePolicyDeniedError("tenant_ai_held")`. The tenant cannot lift it. Set and release require a platform permission (reuse `platform.ai_policy:manage` or add `platform.ai_tenant_hold:manage`; see question 3) through the existing platform operation framework, audited with the platform audit mechanism of ADR-0045 and written to the tenant audit log so the tenant sees why. Gap 21 uses the same table with reason `spending` if automatic suspension is chosen.
5. *Roles.* Document the two permissions and ship a declared permission-grant migration (ADR-0060) only if the owner decides `ai.policy:*` is a non-authority permission eligible for additive grants (question 5).

**Option B: tenant choice replaces alias.** The tenant names a model; the product requests it directly. Rejected: it breaks the alias contract, lets a tenant reach models the platform did not intend, and moves provider knowledge into products.

**Option C: parent-to-child inheritance now.** A parent sets a ceiling that children cannot exceed. Deferred: hierarchy is structural only today, so this needs a new authority rule (who may set a ceiling, how it interacts with deny and subtree scope). Recommended as a later, separately decided phase. Version 1 inherits only the installation-wide policy and the platform alias set.

## 5. Proposed architecture

Everything stays in `saas_os/control_plane/inference` and is exported from `saas_os.inference`. No adapter, secret or egress code changes. Product code calls the same `run_inference(alias=...)`.

```
tenant admin      -> settings service (ai.policy:manage/read) -> ai_tenant_* tables (RLS)
platform operator -> hold service (platform permission)       -> ai_tenant_holds (platform table)
request -> admission (entitlement) -> load_snapshot (hold? policy? grants? ranks) -> evaluate -> send
```

## 6. API and interface design

Python (stable public API, additive):
- `list_eligible_models(caller, tenant_id, *, use_case: str | None = None) -> tuple[EligibleModelView, ...]`
- `set_destination_rank(caller, tenant_id, *, use_case, provider_key, model_id, rank: int | None) -> None`
- `set_tenant_ai_hold(operator_caller, tenant_id, *, reason: HoldReason) -> None` and `release_tenant_ai_hold(...)`
- `read_tenant_ai_status(caller, tenant_id) -> TenantAIStatus` (enabled, held and reason code only, grant counts, first-ranked model per use case)

HTTP (see question 1): an opt-in `ai_settings_router` under `/v1/tenants/{tenant_id}/ai`: `GET /status`, `GET /models`, `PUT /enabled`, `PUT /use-cases/{use_case}/models/{provider}/{model}` (grant, rank, enabled). Each route declares exactly one policy, as `assert_route_policies` requires (`api/route_policy.py`). Handlers use `user_caller(context)` (service accounts refused) and map failures to the shared error vocabulary, keeping the indistinguishable refusal for unknown versus closed tenants that the service already uses. This requires an ADR-0054 amendment relaxing the import-linter rule for this one router, or the router stays product-owned (option H2 in question 1).

## 7. Database and migration implications

- One migration (parent `e2b7c4d9a1f6`): add nullable `preference_rank smallint` to `ai_tenant_destination_grants` (additive, no backfill, no default, brief lock); create `control_plane.ai_tenant_holds` (platform-owned, written through the platform-config role per ADR-0056).
- Tenant isolation classification (`core/tenancy/isolation.py`) and retention class (`core/tenancy/retention.py`) must be set for `ai_tenant_holds`, proven by `test_rls_coverage_sweep_integration.py` and `test_isolation_classification.py`.
- Downgrade drops the column and table, which loses ranks and holds (document it).
- Release label: **0.Y.0** (migration).
- Not verified: lock behaviour of the column add on a production-sized grants table (the table is small by construction).

## 8. Authorization and security model

- Only `ai.policy:manage` holders change settings; support access stays excluded (`authorization.py:330-335`); service accounts and system callers cannot change tenant policy (existing rule kept).
- A tenant never reads or writes another tenant's settings (RLS on all tenant tables plus the `tenant_session_scope` and `lock_open_tenant` path).
- The eligibility view is read-only and returns only catalogue facts the tenant may know (provider and model names, declared data handling). It returns no endpoints, credential names or other tenants' data.
- The hold is platform authority only. A tenant admin cannot clear it, and holding fails closed.
- Credentials: unchanged. No value enters a browser, table or log. New code must not import the secrets provider.
- Outbound: unchanged. This proposal does not change what the platform can reach.
- Defaults: AI stays disabled for new tenants. No code path creates a policy row implicitly.

## 9. Backwards compatibility

Additive. With `preference_rank` null and no hold rows, call behaviour is identical. `grant_destination` becoming stricter is a behaviour change for callers that granted an ineligible model; it is called out in the changelog and the consumer guide. New public names go into `tests/architecture/public_api_snapshot.txt` via `scripts/public_api_snapshot.py --write` after review. No changed or removed signatures are planned.

## 10. Acceptance criteria (testable)

1. **Default off.** A new tenant has no policy row; `run_inference` raises `tenant_policy_absent_or_disabled`; `read_tenant_ai_status` reports `enabled=False`.
2. **Isolation.** Tenant B's admin cannot read or write tenant A's settings or hold status; the refusal for an unknown tenant id is identical (existing F-E pattern).
3. **Permissions.** Ordinary members, holders of only `ai.policy:read`, service accounts, system callers, support access and API keys cannot change settings; each refused attempt writes a `denied` audit row.
4. **Eligibility.** For a catalogue with a disabled provider, a retired model, a residency mismatch, a retention excess, a training-use conflict and a missing capability, `list_eligible_models` reports `eligible=False` with exactly the matching reason code, and `run_inference` agrees.
5. **Selection.** Re-ranking changes which granted model `run_inference` uses for the same alias with no code change; a model outside the alias cannot be ranked; an ineligible model cannot be granted.
6. **Invalid configuration.** Unknown provider or model, duplicate or negative ranks and unknown reason codes are refused with typed errors and no partial write.
7. **Provider failure.** A disabled or failing provider moves to the next granted candidate only; if none remain the typed refusal is returned and no content is sent to a non-granted model.
8. **Immediate disablement.** After `set_tenant_ai_policy(enabled=False)` or a hold, the next request is refused, with a test around the commit using two concurrent requests. Documented limit: an attempt already past `_begin_attempt` completes.
9. **Hold authority.** A tenant admin cannot release a hold; a hold survives a tenant policy toggle; release writes platform and tenant audit rows.
10. **Secrets.** A static test and a log-capture test prove no credential value or `credential_ref` appears in any new return value, audit metadata or log line.
11. **Audit.** Every change writes a same-transaction audit row with a closed action name (`ai.policy.set_rank`, `ai.policy.hold`, `ai.policy.release_hold`); a failed audit write rolls the change back.
12. **Negative controls.** Removing the hold check, grant-time validation, the RLS predicate or the permission check each fails a named test.

## 11. Automated test strategy

Unit tests for reason-code mapping. Integration tests on the disposable Postgres fixture `tests/support/ai_inference_world.py` using `FakeAdapter` only (no real provider, no network, no cost). Migration test beside `test_ai_inference_configuration_migration.py` (upgrade, downgrade, RLS). Architecture tests: public API snapshot, import-linter boundary, and `test_route_policy.py` if a router is added. The RLS coverage sweep. A property test: for random grants, ranks, preferences and catalogues, `list_eligible_models.eligible` equals `evaluate` success.

## 12. Operational considerations

Holds are an operator runbook item (`docs/OPERATIONS.md`). The eligibility view reads catalogue tables per call; it is bounded by catalogue size and needs no cache in v1. A held or disabled tenant produces refusals, so alerting is on refusal rate, which depends on the observability backend decision (ADR-0009). Not verified: behaviour on a production-sized catalogue; any live provider (none is configured or called by this work).

## 13. Dependencies

- Gap 21 consumes `ai_tenant_holds` (optional, for automatic suspension) and the selected-model ranks.
- Gap 22 reads the status and the eligibility view for the settings summary.
- ADR-0054 amendment (router import boundary, hold, rank). ADR-0060 only if role grants ship. No dependency on the pending tenant-owned-credentials decision.

## 14. What could not be verified

Whether `ai.policy:manage` counts as non-authority for ADR-0060; the behaviour of an attempt that straddles a hold; any real provider; `core/rbac/principal.py` was not read for further use of the word "workspace".

## 15. Open questions only the owner can answer

1. Exposed surface: (H1) opt-in `ai_settings_router` with an ADR-0054 amendment relaxing the import boundary for it; (H2) Python API only, products own their routes (consistent with `HTTP-CAPABILITY-MATRIX.md` row 3.8, where usage reports are product-owned); (H3) Python API first, router later. Recommendation: H3.
2. Is tenant ranking (Option A.2) acceptable, or should alias order stay platform-only?
3. Hold permission: reuse `platform.ai_policy:manage` or add `platform.ai_tenant_hold:manage`? Recommendation: add a distinct permission for audit clarity.
4. May grant-time validation refuse a grant that was previously accepted?
5. Is `ai.policy:*` eligible for an ADR-0060 additive grant migration, or must products bind it themselves?
6. Parent-to-child inheritance: out of v1 (recommended) or in?

## 16. Recommendation

Option A with H3, in two steps: **20a** eligibility read, grant-time validation, ranks, permission documentation; **20b** platform hold. Keep inheritance out of v1. Vehicle: dated amendment of ADR-0054 (the #224 and #205 precedent), not a new ADR. Label 0.Y.0 (migration).

## 17. Definition of done

Implemented as above; criteria 1 to 12 pass with negative controls; migration upgrade and downgrade tested; public API snapshot, CHANGELOG, CONSUMER-GUIDE section 14, AI-INFERENCE-CONTRACTS and the ADR-0054 amendment updated; 7/7 required checks green on the merge commit; reviewed; released through `docs/RELEASING.md`; owner decisions recorded in section 18. **Gap 20 is not closed until then.**

## 18. Owner decisions

*Not yet recorded. Implementation is a separate approval.*
