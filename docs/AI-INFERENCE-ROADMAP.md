# AI Inference Roadmap — governed provider and model management

Status: Phase AI-A (architecture and contracts) was written on 2026-10-16 and reconciled with owner decisions in four passes. ADR-0054 and ADR-0055 remain **Proposed**. Each phase needed its own explicit owner authorization: AI-B was authorized on 2026-10-16 with R1–R4, and AI-C to AI-H on 2026-10-17. **AI-B to AI-H are implemented and merged into `main`** (pull request #53, merge commit `0598a9a`; implementation records below). Q11 was settled with evidence in AI-D: the public consumer interface is the facade `saas_os.inference`. Streaming, tenant-owned credentials, provider-report reconciliation, hard token caps and the Bedrock and Vertex AI protocols are not implemented, and the owner decisions listed in the AI-C to AI-H record remain open.

Design: [ADR-0054](ADR/0054-governed-ai-inference-subsystem.md) (architecture, decision register), [ADR-0055](ADR/0055-ai-data-governance-and-destination-authorization.md) (data governance), [threat model](architecture/AI-INFERENCE-THREAT-MODEL.md), [contracts](architecture/AI-INFERENCE-CONTRACTS.md). This roadmap does not replace `docs/IMPLEMENTATION-ROADMAP.md` or `docs/P-ROADMAP.md`. Deferred findings go into the existing ledger in `docs/P-ROADMAP.md` ("Deferred issue ledger"); no second ledger is kept here.

Phase names carry the prefix "AI-" so they cannot be confused with ADR-0045's Phases B–F.

Every phase uses the template of `docs/IMPLEMENTATION-ROADMAP.md`: Objective, Scope, Dependencies, Tests, Security Requirements, Acceptance Criteria, Rollback, Authorization gate.

## Dependency order (approved in principle, 2026-10-16)

```
AI-A ──> AI-B ──> AI-C ──> AI-D ──> AI-E
         (egress,  (config +  (governed   (expanded tenant
          adapters) minimum    inference;  configuration,
                    tenant     consumer    tenant-owned
                    policy)    API after   credentials)
                               Q11)
                               │
                               ├──> AI-F (durable usage accounting, quotas, budgets)
                               ├──> AI-H (consumer validation, exact-SHA pinning, release)
                               └──> AI-G (additional providers and capabilities)
```

- The minimum tenant policy belongs to AI-C because AI-D depends on it.
- AI-E depends on AI-D and extends what AI-C created; it is never the phase that first creates the policy AI-D needs.
- AI-D records pre-send attempt evidence; AI-F is not the first phase to record an attempt.

## Decision status

Labels and the full list are in ADR-0054 section 12; open owner decisions are in section 12a. Summary relevant to the phases:

| Item | Status | Phase |
|---|---|---|
| Existing package boundaries not weakened; F2 not approved; F3 not approved as the public interface; F1 provisional internal design only | Approved owner decision (Q11, partial) | — |
| Public inference interface and dependency direction | **Open owner decision (Q11). Blocks the consumer-facing inference API** | Before AI-D's consumer API |
| Existing tool registration (`saas_os.control_plane.orchestration.tools`) intact | Approved owner decision; future public interface open (Q1) | — |
| Four configuration permissions in AI-C; `platform.ai_usage:read` in AI-D with its operation; two possible recovery steps accepted | Approved owner decision (Q9) | AI-C, AI-D |
| Pre-send attempt evidence in AI-D; reconciliation, quotas and pricing in AI-F | Approved owner decision (Q10) | AI-D, AI-F |
| Entitlement gate and bounded per-tenant concurrency before any production inference path | Approved owner decision (Q12) | AI-D |
| One durable decision record per attempt, plus destination-level evidence | Approved owner decision (Q7) | AI-D |
| Use-case registration: in-process registry of immutable, application-defined use cases; registration alone authorizes nothing; criteria for a future persisted registry recorded | Approved owner decision (Q5) | AI-C or AI-D, whichever first needs it |
| Classification trust model | Approved in principle | AI-D |
| AI egress policy separate from webhooks; AI endpoint baseline | Approved owner decision / established requirement | AI-B |
| Webhook scheme, port, proxy or deadline change | Open owner decision (Q2); ADR-0035 unchanged | None planned |
| Five-timeout model; shared deadline for retries and fallback | Established requirement | AI-B, AI-D |
| Timeout values (5 s / 30 s / 120 s / 60 s / 10 min) | Candidate values (Q3) | AI-B, AI-D |
| Soft token quotas; no hard-cap promise | Established requirement; hard caps open (Q8) | AI-F |

---

## AI-A — Architecture and contracts

- **Objective**: verified repository audit; ADRs, contracts, threat model, decision register, roadmap.
- **Scope**: documentation and architectural decisions only.
- **Status**: documentation written; reconciliation with owner decisions in progress through separately authorized tasks (four passes on 2026-10-16). Q5's initial registry decision is recorded. **Q11 remains unresolved, so the architecture is not ready for implementation of the consumer-facing inference API.** ADR-0054 and ADR-0055 remain Proposed.
- **Authorization gate**: authorized 2026-10-16 for documentation only. See "Phase AI-A record" and the reconciliation records below.

## AI-B — Shared egress and provider foundations

- **Objective**: safe shared egress foundations with explicit per-caller policies, plus the two initial protocol adapters. No governance and no consumer API.
- **Scope**:
  1. Webhook regression tests pinning existing behaviour before any change (threat model 4.5).
  2. `saas_os.infra.egress`: move the webhook address predicate, validation and pinning without changing behaviour. Then add explicit, separate policies (threat model 4.3):
     - the **AI endpoint policy** implements ADR-0054 section 8b: HTTPS/443 default, explicit validated ports, narrow private trust, DNS-rebinding and validation-bypass protection, TLS hostname verification with IP pinning where required, a redirect policy that cannot bypass the destination policy, `trust_env=False`, and bounded deadlines under the five-timeout model of section 8a;
     - the **webhook policy** reproduces today's behaviour exactly; ADR-0035 is unchanged.
  3. For AI calls: non-blocking DNS that preserves validation, pinning and the TLS name (threat model 4.6); bounded multi-address attempts; a bounded streamed reader.
  4. Adapter protocol, capability and normalized error types; a fake provider; `openai_chat_completions` and `anthropic_messages` adapters (non-streaming and streaming parsing; streaming not exposed); conformance tests.
  5. Import-boundary validation for the packages AI-B creates: the AI SDK list; adapters private; `infra.egress` imports no Core or Control Plane. Nothing that depends on the Q11 interface.
- **Not in AI-B**: any webhook scheme, port, proxy or deadline change (Q2); any consumer-facing interface (Q11).
- **Dependencies**: AI-A; AI-B's own authorization; decisions R1–R4 of the readiness review below, settled at authorization. Q3 final values are proposed from evidence during the phase.
- **Tests**:
  - the moved SSRF corpus;
  - existing webhook tests and the new regression tests passing unchanged;
  - a real-TLS pinned-connection test;
  - the AI policy ignores environment proxy variables, while the webhook policy keeps its behaviour;
  - allowed and denied schemes and ports under the AI policy, and unchanged acceptance under the webhook policy;
  - AI deadline tests for slow connect, stalled headers, stalled body, cancellation and the shared retry deadline, with connection cleanup asserted;
  - non-blocking DNS with the rebinding tests;
  - byte caps;
  - the adapter conformance suite (contracts section 2.4);
  - a canary-credential scan;
  - negative controls: re-enabling redirects, `trust_env`, a private address, or an over-deadline exchange under the AI policy must each fail a test.
- **Security Requirements**: dedicated review of egress; webhook behaviour identical.
- **Acceptance Criteria**: all gates of `CLAUDE.md` section 8 green on the final tree; webhook behaviour identical; adapters pass conformance; no new runtime dependency (an exact `httpx`/`httpcore` bound, if adopted, is itemized for the owner).
- **Rollback**: revert; webhooks return to their in-module code.
- **Authorization gate**: **authorized by the owner on 2026-10-16** together with decisions R1–R4. Implemented on branch `feat/ai-inference` and merged into `main` by pull request #53 (`0598a9a`). See "AI-B implementation record" below.

### AI-B readiness review (2026-10-16, documentation only)

**Conclusion.** AI-B can be implemented independently of the unresolved consumer-facing inference interface (Q11). This holds only if AI-B stays inside the scope below and the owner settles the four decisions R1–R4 when authorizing it. No AI-B blocker comes from Q11, AI-C or AI-D. The review was done by reading code and tests, not by implementing anything.

**Conditions** (owner's checklist):

| # | Condition | Finding | Evidence |
|---|---|---|---|
| 1 | Egress testable without the final facade | **Met.** The shared egress module (`saas_os.infra.egress`, proposed) is infrastructure; tests drive it with local servers, resolver injection and fake transports, the patterns the webhook tests already use. No consumer API is involved | `tests/core/webhooks/test_webhook_ssrf_policy_unit.py`, `test_webhooks_delivery_integration.py` |
| 2 | Adapters on a stable internal contract without deciding the public API | **Met, with a rule.** The adapter contract (contracts section 2: `AdapterRequest`, `ResolvedTarget`, `OpaqueCredential`, `EgressClient`, normalized errors) is internal to `saas_os.control_plane.inference`. AI-B must not export, document as public, or stabilize the consumer types of contracts sections 3–7, and must create no `saas_os.inference` package; those depend on Q11 | ADR-0054 section 3 |
| 3 | Webhook behaviour preserved and regression-tested | **Met, with a constraint found in review.** The webhook tests patch module attributes of `saas_os.core.webhooks.service`, for example `monkeypatch.setattr(webhooks_service, "_default_resolve_hostname", ...)` and `monkeypatch.setattr(webhooks_service, "_validate_destination", ...)` (`tests/core/webhooks/`). If those functions simply move to `saas_os.infra.egress`, the patches would no longer reach the code that runs, and the tests could pass without testing anything. The extraction must keep these names as seams in the webhook module, looked up at call time and delegating to `infra.egress`, or change the tests deliberately with a non-vacuity check. Either way, a control must show each patched seam still takes effect | `grep` of `tests/core/webhooks` for `monkeypatch.setattr(webhooks_service, ...)` |
| 4 | No existing boundary weakened | **Met.** `saas_os.infra.egress` imports neither Core nor the Control Plane ("Infrastructure does not depend on Core", "… on Products or the AI Control Plane"). `core.webhooks` → `infra.egress` and `control_plane.inference.adapters` → `infra.egress` are permitted directions. AI-B *adds* contracts (AI SDKs only in adapters; adapters private) and removes none | `pyproject.toml` `[tool.importlinter]` |
| 5 | No AI-C configuration schema or permission needed | **Met.** Adapters take the target, credential and egress client as parameters; conformance tests use fake values. No table, migration or permission is needed | Contracts section 2.1 |
| 6 | No unapproved tenant-policy, credential-management or endpoint-trust design needed | **Met if R1 is decided as recommended.** Tenant policy and credential resolution are not touched (fake credentials only). Private-endpoint trust is an established requirement, but its entry semantics (threat model 3.10) are only proposed. AI-B can either ship the AI policy with **no** trust entries (every non-public destination refused) or implement the proposed semantics; that is decision R1 | Threat model 3.10 |
| 7 | Conformance suite does not imply production readiness | **Met with a caveat (R2).** The suite tests adapter behaviour only. No SaaS OS code path calls an adapter with tenant data until AI-D, and no public export exists. However, merged AI-B code reaches every consumer that pins a later SHA, and an external consumer's code cannot be prevented from importing an internal module (ADR-0054 section 3). That residual risk needs an explicit owner choice | ADR-0013 invariant 8; ADR-0015 rule 8 |

**Obligations AI-B carries** (in scope if AI-B is authorized; none is done now):
- New packages are added to the explicit `[tool.setuptools] packages` list, since `tests/architecture/test_namespace_contract.py::test_the_shipped_package_list_matches_the_packages_on_disk` requires it.
- `saas_os/infra/update/policy.py` gives `saas_os/infra/egress/*` and `saas_os/control_plane/inference/*` a category; `saas_os/core/webhooks/*` is already security-relevant. `POLICY_VERSION` (currently `"3"`) is bumped.
- Import-linter contracts are added for the AI SDK list and private adapters; no existing contract is relaxed.
- Webhook policy reproduces today's behaviour exactly (Q2 open); the seams of condition 3 are preserved.
- Timeout values are configurable; see R3.

**Owner decisions (R1–R4 approved on 2026-10-16 as recommended, option (a) in each row; R2 accepts the recorded risk):**

| # | Decision | Options and trade-offs | Approved |
|---|---|---|---|
| R1 | Private-endpoint trust in AI-B | (a) AI-B's AI policy refuses every non-public destination; trust-entry semantics and storage come together in AI-C. Smallest scope; no unapproved design. (b) Approve the trust-entry semantics of threat model 3.10 now and implement matching in AI-B. Earlier testing of private endpoints; commits to a design before its administration exists | (a) |
| R2 | Releasing internal adapters before governed inference exists | (a) Merge AI-B to `main` with adapters internal (no export, no stability promise, no SaaS OS caller). Consumers pinning later SHAs receive code they could misuse, but it gives them no capability raw `httpx` does not. (b) Merge the egress part and keep adapters unmerged until AI-D. (c) Keep all of AI-B unmerged until AI-D. Delays review and integration | (a), risk accepted and recorded in the ledger |
| R3 | Timeout values in AI-B | (a) Configurable values with the candidates (5 s / 30 s / 120 s / 60 s / 10 min) as provisional defaults, clearly marked; no production caller exists until AI-D; final values (Q3) approved before AI-D. (b) No defaults: every value supplied by the caller or configuration | (a) |
| R4 | `httpx` / `httpcore` version bound | IP pinning with the original TLS name relies on httpcore's `sni_hostname` extension (`saas_os/core/webhooks/service.py:319-368`), while `pyproject.toml` requires only `httpx>=0.27`. (a) Add a tested upper bound (a dependency change). (b) Keep the bound unchanged and rely on the real-TLS test to catch a break | (a) |

Not needed for AI-B: Q11 (consumer interface), Q12 (entitlement and concurrency), Q9 (permissions), Q2 (webhook behaviour change, excluded from AI-B), Q3 final values (R3 covers provisional ones).

## AI-C — Configuration and policy foundation

**Status:** Implemented on branch `feat/ai-inference` (2026-10-17) and merged into `main` by pull request #53 (`0598a9a`); see the AI-C to AI-H implementation record.

- **Objective**: provider, model and alias configuration with audited administration, and the minimum tenant AI policy required for safe inference in AI-D.
- **Scope**:
  1. Provider, model and alias configuration in the `control_plane` schema (working names `ai_providers`, `ai_models`, `ai_aliases`, `ai_endpoint_trust`, `ai_platform_policy`) with the tenant-context exclusion policy (as proposed; implemented without RLS, see ADR-0054 section 5, implementation status; writes restricted to a separate database role by ADR-0056); configuration validation; credential references and origin binding; endpoint trust entries.
  2. The **four configuration permissions** (`platform.ai_config:read`, `platform.ai_provider:manage`, `platform.ai_endpoint_trust:manage`, `platform.ai_policy:manage`), each with its operation, through the complete ADR-0045 process (ADR-0054 section 9):
     - ADR-0045 amendment;
     - migration on `ck_platform_grants_permission`;
     - `PLATFORM_OPERATIONS` rows;
     - bootstrap placement;
     - recovery for existing installations (`platform_bootstrap recover`);
     - the approved-importer update;
     - authorization, migration and lifecycle tests.

     `platform.ai_usage:read` is **not** registered in AI-C (Q9).
  3. Configuration operations and `saas-os-operator` subcommands (contracts section 8), platform-audited in the same transaction.
  4. **Minimum tenant AI policy** (ADR-0055 section 7): per-use-case enable or disable; provider and model eligibility; classification-to-destination rules; enabled state; default deny when policy is absent or disabled. It is written through a tenant RBAC permission (proposed `ai.policy:manage`) with same-transaction tenant audit. The exact schema is designed in this phase against the repository's conventions.
  5. The tenant policy references use cases by name. The initial registration model is the selected in-process registry of immutable, application-defined use cases (Q5); no use-case table is created. The registry itself is built in AI-C if the tenant policy validates use-case names against it, otherwise in AI-D.
- **Dependencies**: AI-B; AI-C's own authorization.
- **Tests**:
  - per platform operation: authorized; refused without the permission; refused for a service account and for system purposes; audited in the same transaction; a refused call leaves no change;
  - credential value never in a result, an audit row or a log;
  - an origin change clears the binding;
  - trust entry validation (the always-deny list cannot be trusted);
  - tenant policy: written only with the tenant permission, never by a platform permission; isolated by RLS (cross-tenant, sibling, parent); absent or disabled policy denies;
  - migration upgrade and downgrade; bootstrap and recovery tests for the four permissions; RLS sweep; last-owner invariant unaffected.
- **Security Requirements**: no route; no credential read-back; platform operators cannot write tenant policy.
- **Acceptance Criteria**: full gates green; migration safety analysis (`CLAUDE.md` section 12) recorded; AI-D's policy inputs all exist and deny by default.
- **Rollback**: downgrade migration (additive tables); permissions are never deleted once granted, so a rolled-back deployment keeps grant rows that confer nothing.
- **Authorization gate**: separate explicit authorization. **Not authorized.**

## AI-D — Governed inference

**Status:** Implemented on branch `feat/ai-inference` (2026-10-17) and merged into `main` by pull request #53 (`0598a9a`), without streaming; Q11 settled; see the implementation record.

- **Objective**: governed inference. The consumer-facing inference API is built **only after the Q11 interface and dependency-direction blocker is resolved**. Streaming only when its security and operational requirements can be met.
- **Scope**:
  - the consumer-facing inference API, per the Q11 decision;
  - authorization (`ai.inference:run`) and policy enforcement, using AI-C's minimum tenant policy and never assuming one exists;
  - use-case checks against the in-process registry (Q5), never treated as authorization on their own;
  - per-part classification with fail-closed handling (ADR-0055 section 4);
  - alias and capability validation;
  - bounded retries sharing the original deadline; Redis-backed circuit breaking; safe fallback;
  - **pre-send attempt evidence** (Q10) with one durable decision record per attempt and destination-level evidence (Q7), designed and validated in this phase;
  - **entitlement gate** and **bounded per-tenant concurrency** (Q12), with their design requirements (ADR-0054 section 7): source of truth, server-side enforcement, deny on missing or ambiguous data, coordination across instances (no distributed concurrency limiter exists today), no content on rejection, observable exhaustion, bounded shared capacity;
  - usage integration and provider-outcome correlation;
  - `platform.ai_usage:read` with its usage-reading operation, through the complete ADR-0045 process (Q9);
  - abandoned-attempt reconciliation job.
- **Streaming gate (inside AI-D, separately authorized)**: enable `stream_inference` only when contracts section 6.6's six criteria pass.
- **Dependencies**: AI-C, including the minimum tenant policy; **Q11 resolved** (for the consumer API); the in-process use-case registry; AI-D's own authorization.
- **Tests**:
  - full pipeline with the fake provider;
  - classification: missing, invalid and unsupported values fail closed; an unknown use case is denied; a label above the ceiling is denied; a raised ceiling in code gains nothing the tenant did not grant; `none` still needs a grant and an eligible destination;
  - policy: absent or disabled tenant policy denies;
  - entitlement: absent or ambiguous entitlement denies;
  - concurrency:
    - concurrent requests beyond the per-tenant bound are rejected without sending content;
    - one tenant's load does not consume another tenant's capacity;
    - the bound holds across two application instances;
    - a slot is released on every exit path and expires after a crash;
  - isolation: cross-tenant, sibling and parent tenants; support access never satisfies `ai.inference:run`;
  - retries and fallback: every error category's behaviour; retries and fallback share the deadline; fallback re-authorization; no fallback after possible acceptance;
  - evidence: no content sent when a required evidence write fails; one decision record per attempt; destination changes distinguishable; no payload in logs or audit rows;
  - negative controls for each fence.
- **Security Requirements**: dedicated security review; ADR-0013 invariants 1, 3, 4, 5, 7, 8 demonstrably enforced for inference.
- **Acceptance Criteria**: full gates green; reference consumer exercises one inference call against a fake endpoint through the Q11 interface; no production inference path exists without the entitlement gate and the concurrency bound.
- **Rollback**: disable via configuration (all providers disabled); revert.
- **Authorization gate**: separate explicit authorization. **Not authorized.**

## AI-E — Expanded tenant configuration

**Status:** Implemented on branch `feat/ai-inference` (2026-10-17) and merged into `main` by pull request #53 (`0598a9a`), without tenant-owned credentials (owner decision required).

- **Objective**: extend the tenant AI policy that AI-C created; tenant-owned credentials if approved. AI-E does not create the minimum policy AI-D depends on.
- **Scope**: additional tenant preferences; residency and retention settings; tenant-owned credentials under the credential-isolation model of ADR-0054 section 6.
- **Dependencies**: AI-D.
- **Tests**: isolation (RLS, sibling, parent); credential never readable back; rotation and revocation take effect on the next request; a tenant credential is never used for another tenant.
- **Authorization gate**: separate explicit authorization; tenant-owned credentials need an explicit owner decision. **Not authorized.**

## AI-F — Durable usage accounting and budgets

**Status:** Implemented on branch `feat/ai-inference` (2026-10-17) and merged into `main` by pull request #53 (`0598a9a`): pricing, cost estimates, soft token quota; provider-report reconciliation and the ledger retention class remain open.

- **Objective**: durable usage reconciliation and accounting, quotas with an honest enforcement model, and pricing and monetary budgets once their guarantees are established. AI-F builds on AI-D's attempt evidence; it is not the first phase to record an attempt.
- **Scope**:
  - reconciliation between attempts and provider outcomes;
  - actual usage accounting;
  - handling of incomplete, failed, cancelled and ambiguous outcomes;
  - **soft** token quotas, documented as best effort;
  - a hard-cap reservation design only if separately decided (Q8; requirements in ADR-0054 section 7);
  - pricing table and versions; cost estimates with provenance;
  - attempt-record retention class.
- **Dependencies**: AI-D.
- **Acceptance Criteria**: no hard token ceiling and no hard monetary budget is claimed unless reservation, concurrency and failure semantics are designed, implemented and tested.
- **Authorization gate**: separate explicit authorization. **Not authorized.**

## AI-G — Additional providers and capabilities

**Status:** Gemini `generateContent` implemented on branch `feat/ai-inference` (2026-10-17) and merged into `main` by pull request #53 (`0598a9a`); Bedrock, Vertex AI, embeddings, reranking and other modalities not implemented.

- **Objective**: Gemini-native, Bedrock, Vertex AI, embeddings, reranking, other modalities — each only on a concrete consumer requirement, each with its own adapter conformance and threat review.
- **Authorization gate**: separate explicit authorization per addition. Not authorized.

## AI-H — Consumer validation, exact-SHA pinning and release

**Status:** Consumer validation implemented on branch `feat/ai-inference` (2026-10-17) and merged into `main` by pull request #53 (`0598a9a`); no release has been made and the reference consumer's pin has not moved.

- **Objective**: consumer integration tests from an installed wheel; public API compatibility tests; consumer guide section; migration guidance; exact-SHA example pins; release readiness.
- **Dependencies**: AI-D (and AI-F if budgets are claimed).
- **Authorization gate**: separate explicit authorization; publication (commit, push, PR, merge) needs its own authorization. Not authorized.

---

## Phase AI-A record (2026-10-16)

### Baseline

- This repository, branch `main`, HEAD `7ab94229a15a1c01be60edbed66946598c0bb239`, equal to `origin/main` (0 ahead, 0 behind). Working tree clean before the run.

### Evidence gathered

Read-only inspection of: import-linter contracts (`pyproject.toml`); `saas_os/control_plane/data_authorization`, `orchestration`, `self_learning/adaptive`; `saas_os/core/webhooks/service.py` egress; the `SecretsProvider` package under `saas_os/infra`; `saas_os/core/crypto`; `saas_os/core/usage`; `saas_os/infra/ratelimit`; `saas_os/core/platform_authority`; `saas_os/core/authority/caller.py`; `saas_os/ops/operator_cli.py`; ADR-0004, 0012, 0013, 0015, 0035, 0037, 0041, 0045; `docs/AI-CONTROL-PLANE.md`; `docs/SECURITY.md` 6.1; `docs/ARCHITECTURE.md` section 2. Python check: on the repository's Python 3.13.14, `ipaddress` reports the NAT64 address `64:ff9b::808:808` as global (`is_global` is `True`).

The prior audit's hypotheses, checked:

| Hypothesis | Result |
|---|---|
| No complete inference subsystem | Confirmed: no provider client, SDK, routing or agent runtime |
| `httpx` reusable | Confirmed (runtime dependency) |
| `SecretsProvider` reusable | Confirmed with limits: environment only, no rotation, version, listing or tenant scope |
| `EncryptionService` reusable | Confirmed; suits tenant-owned credentials later |
| Usage events and quotas reusable | Confirmed with limits: no model/provider dimension, no reservation, missing limit = unlimited |
| Platform permissions reusable | Confirmed; vocabulary is closed, additions are an ADR-0045 amendment plus migration |
| Audit logging reusable | Confirmed: tenant `record_in_transaction`, platform `record_platform_event_in_transaction` |
| Webhook egress controls reusable | Partly: predicate, pinning, no-redirects reusable; `trust_env`, ports, deadlines, DNS, body reading, trust entries missing |
| `saas_os.control_plane.inference` location | Appropriate, conditional on O1 |
| `saas_os.api` may not import the Control Plane | Confirmed (import-linter) |

### Deliverables

| File | Purpose |
|---|---|
| `docs/ADR/0054-governed-ai-inference-subsystem.md` (new, Proposed) | Primary architecture; decision register D1–D12; owner decisions O1–O3 |
| `docs/ADR/0055-ai-data-governance-and-destination-authorization.md` (new, Proposed) | Classification, destination authorization, default deny, tenant policy |
| `docs/architecture/AI-INFERENCE-THREAT-MODEL.md` (new) | Threat model; webhook egress reuse and extraction plan |
| `docs/architecture/AI-INFERENCE-CONTRACTS.md` (new) | Adapter, capability, error, `run_inference`/`stream_inference`, usage, administration contracts |
| `docs/AI-INFERENCE-ROADMAP.md` (new) | This roadmap and record |
| `docs/ADR/README.md` (edited) | Index rows for 0054 and 0055 |
| `docs/AI-CONTROL-PLANE.md` (edited, section 8 only) | Points the open model/provider question to ADR-0054 for inference |
| `docs/P-ROADMAP.md` (edited, ledger rows only) | Deferred findings from this phase |

### Acceptance criteria

| # | Criterion | Result |
|---|---|---|
| 1 | Repository state and boundaries verified | Met (baseline and evidence above) |
| 2 | Twelve decision areas dispositioned | Met (ADR-0054 section 13) |
| 3 | Five principal decisions resolved or flagged | Met (ADR-0054 section 13, second table) |
| 4 | Adapter strategy without vendor SDK coupling | Met (D2) |
| 5 | Consumer API detailed without inventing authorization semantics | Met: uses existing typed callers and `can()`; one new tenant permission and five platform permissions proposed, flagged |
| 6 | Streaming semantics and release criteria | Met (contracts section 6) |
| 7 | Classification, destination authorization, default deny explicit | Met (ADR-0055) |
| 8 | Threat model covers the listed issues | Met (threat model section 3) |
| 9 | Webhook egress reuse risks documented with evidence | Met (threat model section 4) |
| 10 | Usage, token quotas, retries, fallback defined | Met (ADR-0054 sections 7–8; contracts sections 4, 7) |
| 11 | Roadmap with scope and independent gates | Met (this document) |
| 12 | Existing user changes preserved | Met: tree was clean; only the files listed above changed |
| 13 | No runtime implementation or database change | Met: documentation files only |
| 14 | No commit, push, PR or merge | Met |
| 15 | Unresolved decisions and risks presented | Met (O1–O3; ledger rows) |

### Validation

Documentation only. No code, test, migration or dependency changed, so code gates (pytest, pyright, ruff, import-linter, migrations, Docker) are unaffected and were not run. Checked: `git status` and `git diff --stat` show only the files above; no file outside `docs/` changed.

---

## Decision reconciliation record (2026-10-16, first pass)

*Superseded in part by the second pass below.* Its labels O1–O3 and E1–E3 are replaced by the status labels of ADR-0054 section 12. The first pass applied E1–E3 to webhooks; the second pass keeps webhook behaviour unchanged. Its candidate-free timeout wording is replaced by the five-timeout model with candidate values. Its Q9 is answered in part: no dummy operation is created; `platform.ai_usage:read` comes with its AI-D read path. The text below is kept as the record of that pass.

Documentation-only task, authorized 2026-10-16. **AI-B is not authorized.**

### Baseline

Branch `main`, HEAD `7ab94229a15a1c01be60edbed66946598c0bb239`. Pre-existing uncommitted changes, all from Phase AI-A and preserved: the five new Phase AI-A documents, plus edits to `docs/ADR/README.md`, `docs/AI-CONTROL-PLANE.md` and `docs/P-ROADMAP.md`.

### Decisions recorded

O1 (public facade), O2 (five platform permissions for AI-C), O3 (classification trust model), the AI-C/AI-D/AI-E sequencing, and E1–E3 (AI-B egress requirements). All are recorded in ADR-0054 section 12, ADR-0055 sections 4 and 7, the threat model 3.6–3.8 and 4, the contracts document, this roadmap, `docs/ARCHITECTURE.md` section 2 (approved, not implemented), `docs/AI-CONTROL-PLANE.md` section 8 and the ADR index.

### Contradictions found and how they were handled

| # | Finding | Resolution |
|---|---|---|
| 1 | O1 read literally ("products must not import internal `saas_os.control_plane` modules") conflicts with the reference consumer's documented tool-registration import (`examples/reference-consumer/reference_consumer/tools.py:25`) | Not overridden. The documents apply O1 to `saas_os.control_plane.inference`; the broader question is ADR-0054 Q1 and a ledger row |
| 2 | E2's HTTPS/443 default, applied to tenant-supplied webhook URLs, conflicts with ADR-0035, which accepts `http` and any port | Not decided. ADR-0054 Q2; ADR-0035 to be amended in AI-B after the owner decides |
| 3 | O2 places all five permissions in AI-C, but ADR-0045's operation table requires an operation per permission, and the usage read has no ledger until AI-D | Not decided. ADR-0054 Q9 |
| 4 | Phase AI-A documents gave concrete timeout and size values (connect 5 s, 8 MiB, 30 s webhook deadline) | Removed; values are AI-B implementation decisions (E3, Q3) |
| 5 | Phase AI-A placed tenant model allowlists in AI-E; the owner's minimum policy includes eligible providers **and models** | Models moved into AI-C's minimum policy; AI-E keeps preferences, residency/retention and tenant credentials |
| 6 | The owner used short permission names (`ai_config:read`, …); the repository's vocabulary requires the `platform.` prefix | Full identifiers used everywhere, with the mapping stated in ADR-0054 section 9 |
| 7 | Phase AI-A documents placed the consumer API in `saas_os.control_plane.inference.api` | Replaced by the facade; the internal module is `entrypoints` (provisional) |

### Acceptance criteria

| # | Criterion | Result |
|---|---|---|
| 1 | O1, O2, O3 recorded accurately | Met |
| 2 | Facade and internal boundary documented without weakening import restrictions | Met; the `saas_os.api` contract is unchanged and applies transitively through the facade; the conflict is recorded as Q1 |
| 3 | Five permissions defined and deferred to AI-C | Met; registration timing of `platform.ai_usage:read` is Q9 |
| 4 | Classification trust limitation documented | Met (ADR-0055 section 4) |
| 5 | AI-C establishes the minimum tenant policy | Met |
| 6 | AI-E keeps expanded configuration and tenant credentials | Met |
| 7 | E1–E3 recorded as approved AI-B design requirements | Met |
| 8 | Webhook compatibility and regression requirements documented | Met (threat model 4.4–4.6) |
| 9 | Documents agree | Met as far as checked (cross-document search for stale references) |
| 10 | No runtime code, tests, schemas, dependencies or executable permissions changed | Met: only files under `docs/` |
| 11 | No commit, push, branch, PR or merge | Met |
| 12 | Remaining questions listed explicitly | Met (ADR-0054 Q1–Q9) |

---

## Decision reconciliation record (2026-10-16, second pass)

*Superseded in part by the third pass below:* Q7, Q9, Q10, Q11 (partly) and Q12 are now approved owner decisions, and Q5 has a recorded criterion.

Documentation-only task, authorized 2026-10-16. **AI-B and later phases are not authorized, and ADR-0054 and ADR-0055 remain Proposed.**

### Baseline

Branch `main`, HEAD `7ab94229a15a1c01be60edbed66946598c0bb239`, equal to `origin/main` (0 ahead, 0 behind). Nothing staged. Uncommitted changes from the earlier passes, all preserved:
- modified: `docs/ADR/README.md`, `docs/AI-CONTROL-PLANE.md`, `docs/ARCHITECTURE.md`, `docs/P-ROADMAP.md`;
- untracked: the five AI-A documents.

### Decisions reconciled

| Owner decision (2026-10-16) | Recorded in |
|---|---|
| 1. Public facade; trusted callers; no inference route; `saas_os.api` rule unchanged; dependency direction **unresolved**; existing tool registration preserved | ADR-0054 section 3 (verified transitive effect, options F1–F3, Q11, Q1); `docs/ARCHITECTURE.md` section 2; `docs/AI-CONTROL-PLANE.md` section 8; ledger |
| 2. AI egress policy separate from webhook policy; AI endpoint baseline; ADR-0035 unchanged | ADR-0054 section 8b; threat model 3.6, 3.7, 4.3–4.5; ledger |
| 3. Five-timeout model; candidate values only; shared deadline; transport limitations | ADR-0054 sections 8, 8a; threat model 3.8; contracts sections 4–6 |
| 4. Permission names verified (`platform.<resource>:<action>`); `platform.ai_usage:read` with its AI-D read path, no dummy operation | ADR-0054 section 9; roadmap AI-C, AI-D; Q9 |
| 5. ADRs stay Proposed; status labels | ADR-0054 section 12 (12.1–12.4, 12a), section 13; ADR-0055 status and Decision; ADR index |
| 6. Audit and usage event model | ADR-0054 section 7a; Q7 |
| 7. Soft token quotas; hard-cap design requirements | ADR-0054 section 7; contracts section 4; roadmap AI-F; Q8 |
| 8. Classification model and residual risk; registration mechanism open | ADR-0055 section 4; contracts section 3; Q5 |
| 9. Phase sequencing | This roadmap |

### Conflicts kept as open questions

| # | Conflict | Kept as |
|---|---|---|
| 1 | The existing API contract is transitive, so `saas_os.api` cannot import a facade that imports the Control Plane. A dependency-inverted facade would avoid that only by weakening the boundary | Q11 (options F1–F3) |
| 2 | ADR-0045's test requires every permission to have an operation; the owner placed `platform.ai_usage:read` with the AI-D read path | Q9 (one or two registration rounds) |
| 3 | The owner's phase list puts "durable usage accounting" in AI-F and "usage integration" in AI-D, while the governance pipeline needs per-attempt records before sending | Q10 |
| 4 | The owner's phase list does not place the entitlement gate and the concurrency limit | Q12 |
| 5 | The existing in-process `ToolRegistry` convention may or may not settle use-case registration | Q5 |

### Validation

Recorded in the final report of this pass. Documentation only.

---

## Decision reconciliation record (2026-10-16, third pass)

*Superseded in part by the fourth pass below:* Q5 is now an approved owner decision (in-process registry of immutable, application-defined use cases) and is no longer open.

Documentation-only task, authorized 2026-10-16. **AI-B and later phases are not authorized. ADR-0054 and ADR-0055 remain Proposed.**

### Baseline

Branch `main`, HEAD `7ab94229a15a1c01be60edbed66946598c0bb239`, equal to `origin/main` (0 ahead, 0 behind). Nothing staged. Uncommitted changes from the earlier passes, all preserved:
- modified: `docs/ADR/README.md`, `docs/AI-CONTROL-PLANE.md`, `docs/ARCHITECTURE.md`, `docs/P-ROADMAP.md`;
- untracked: the five AI-A documents.

### Decisions recorded

| Decision | Where |
|---|---|
| Q11: boundaries not weakened; F2 not approved; F3 not approved as the public interface; F1 provisional internal design only; public interface and dependency direction open and blocking the consumer API; follow-up investigation defined; candidate approaches C1–C3 labelled as proposals | ADR-0054 section 3, 12, 12a; contracts section 1; threat model 3.1; `docs/ARCHITECTURE.md` section 2; `docs/AI-CONTROL-PLANE.md` section 8; ledger |
| Q9: four configuration permissions in AI-C, `platform.ai_usage:read` in AI-D with its operation; two recovery steps accepted | ADR-0054 section 9; roadmap AI-C, AI-D |
| Q10: pre-send attempt evidence in AI-D; AI-F reconciliation, quotas, pricing; no durability claim beyond the chosen mechanism | ADR-0054 sections 4, 7; ADR-0055 section 6; contracts section 7; threat model 3.15; roadmap |
| Q12: entitlement gate and bounded per-tenant concurrency required in AI-D, with design requirements; distributed concurrency limiter recorded as a gap | ADR-0054 section 7; contracts sections 4, 5; threat model 3.12; roadmap AI-D |
| Q5: selection criterion (Option A in-process versus Option B persisted, audited); rules that hold under either; decision needed before AI-C | ADR-0055 section 4; ADR-0054 section 12a; roadmap AI-C |
| Q7: one durable decision record per attempt with destination-level evidence; four kinds of evidence; design requirements | ADR-0054 section 7a; ADR-0055 section 6 |

### Remaining open owner decisions

Q11 (blocker for the consumer API), Q5 (before AI-C), Q1, Q2, Q3, Q6, Q8 (ADR-0054 section 12a).

---

## Decision record and AI-B readiness review (2026-10-16, fourth pass)

Documentation-only task, authorized 2026-10-16. **AI-B and later phases are not authorized. ADR-0054 and ADR-0055 remain Proposed.**

- **Baseline:** branch `main`, HEAD `7ab94229a15a1c01be60edbed66946598c0bb239`, equal to `origin/main`. Nothing staged. The nine documents from the earlier passes are present and preserved.
- **Q5 recorded** as an approved owner decision: an in-process registry of immutable, application-defined use cases; registration alone authorizes nothing; eight independent checks; criteria for reconsidering a persisted registry kept as guidance (ADR-0055 section 4; ADR-0054 section 12.1; contracts section 3).
- **AI-B readiness review** recorded under AI-B. AI-B is independently implementable within its scope, subject to R1–R4. One new constraint was found: the webhook tests patch module attributes of `saas_os.core.webhooks.service`, so the extraction must keep those seams effective.
- **Q11** remains open and blocks the consumer-facing inference API.
- **Concurrency:** the distributed concurrency gap remains open. The Redis lease is a candidate with the required design coverage listed (ADR-0054 section 7).
- **Remaining open owner decisions:** Q11, Q1, Q2, Q3, Q6, Q8; R1–R4 for AI-B authorization.

---

## AI-B implementation record (2026-10-16/17; implemented on branch `feat/ai-inference`; merged by pull request #53)

Authorized by the owner on 2026-10-16 with decisions R1–R4. **Not staged, committed, pushed or released. AI-C and later phases are not authorized.**

### Baseline

Branch `main`, HEAD `7ab94229a15a1c01be60edbed66946598c0bb239`, equal to `origin/main`. Before the run, the only uncommitted work was the AI-A documentation:
- modified: `docs/ADR/README.md`, `docs/AI-CONTROL-PLANE.md`, `docs/ARCHITECTURE.md`, `docs/P-ROADMAP.md`;
- untracked: the five AI-A documents.

It was preserved, and a backup copy was kept outside the repository.

### Delivered

- `saas_os/infra/egress/` (new):
  - shared address primitives, moved unchanged from webhook delivery;
  - `StrictEgressClient` / `StrictEgressPolicy`, Deadline, the error hierarchy, and the HTTP-stack guard (ADR-0054 section 8c).
- `saas_os/core/webhooks/service.py`: the moved functions are replaced by module-level aliases; webhook behaviour is unchanged (ADR-0035).
- `saas_os/control_plane/inference/` (new, internal): `egress_config` (provisional settings, R3) and `adapters` (OpenAI-compatible, Anthropic Messages, fake; internal contract; normalized errors).
- `pyproject.toml`:
  - `httpx>=0.28.1,<0.29` and `httpcore>=1.0.9,<1.1` (R4);
  - three new packages;
  - three new import-linter contracts (19 total, none relaxed).
- `saas_os/infra/update/policy.py`: version 4. Egress is `security_control` and inference is `provider_boundary`; without this, both would have been auto-applied as `internal`. `docs/AUTO-UPDATE-CLI.md` was updated to match.
- Tests:
  - `tests/infra/egress/`: unit tests and real-socket/real-TLS tests;
  - `tests/control_plane/inference/`;
  - `tests/core/webhooks/test_webhook_shared_egress_unit.py`;
  - `tests/architecture/test_ai_inference_boundaries.py`;
  - `tests/support/egress_support.py`;
  - the policy-version assertions in `tests/infra/update/`.

**Deferred, by decision or scope:** streaming; provider retries and fallback; private-endpoint trust (R1); any configuration or credential storage, permission, migration, governance, consumer interface or route.

### Negative controls

Each control was deliberately weakened, the relevant tests were run, and the file was restored byte for byte (SHA-256 verified). Every weakening was caught:

| Control removed | Result |
|---|---|
| Address predicate (everything public) | 120 tests failed |
| `sni_hostname` not passed | 9 failed |
| Environment proxies trusted | 1 failed |
| Redirects followed | 6 failed |
| Total deadline removed | 4 failed |
| Response byte limit removed | 2 failed |
| HTTP-stack version guard removed | 6 failed |
| All-or-nothing address check weakened | 14 failed |

The architecture tests also show each new import contract BROKEN when a forbidden import is written into a real module, and the module restored afterwards.

### Validation on the final tree

| Gate | Command | Result |
|---|---|---|
| Lint | `ruff check .` | passed |
| Format | `ruff format --check .` | passed (833 files); formatting the AI-A contracts document's Python code blocks was required for this gate |
| Types | `pyright` | 0 errors |
| Import boundaries | `lint-imports` | 19 kept, 0 broken |
| Default suite | `pytest` | 3958 passed, 89 skipped (88 Caddy, 1 POSIX; pre-existing), 0 failed |
| Integration | `scripts/check-integration.sh`, disposable PostgreSQL 16 and Redis 7 | 2706 passed, 0 skipped, gate green; containers removed |
| Packaging | `scripts/check-packaging.sh` | 7 passed |
| Dependencies | `pip-audit` | no known vulnerabilities |
| Frontend audit | `scripts/npm_audit_gate.py frontend` | passed (the accepted `braces` exception only) |
| Secrets | `detect-secrets-hook --baseline .secrets.baseline` over tracked files; `detect-secrets scan` over the new files | no findings; baseline unchanged (SHA-256 `99f3a26a…`) |
| Docker | `scripts/check-docker.sh` | passed: backend and frontend images built with the new bounds, runtime checks green, worker executed the job, no container left |

After the default suite, two test files gained `# pragma: allowlist secret` comments, and `pyproject.toml` and `compat.py` comments were corrected; the affected checks and tests were re-run and passed.

The tests validate egress and adapter behaviour against local servers and fakes. They do not validate behaviour against real providers, and nothing here is a governed inference path.

## AI-C to AI-H implementation record (2026-10-17; implemented on branch `feat/ai-inference`; merged by pull request #53)

Authorization: the owner's standing authorization for AI-B through AI-H
(2026-10-17). Not authorized and not done: staging, commit, push, pull
request, merge, release, deployment. ADR-0054 and ADR-0055 stay Proposed.

### Delivered

| Phase | Delivered | Not delivered (reason) |
|---|---|---|
| AI-C | Migration `e4b8c2d6f1a3`; five global and three tenant tables; four platform permissions and operations (ADR-0045 amendment); configuration operations with credential references and origin binding; private-endpoint trust in the strict egress client; minimum tenant AI policy; `saas-os-operator ai-*` (13 commands) | -- |
| AI-D | Migration `a7f3c91e2d48`; `saas_os.inference` (Q11 settled: C1 + F1); `run_inference` with authority, classification, eligibility (including the ADR-0013 evaluator), entitlement, cross-instance concurrency lease, pre-send attempt evidence, settlement with usage outbox, retries and fallback within one deadline, shared circuit breaker; `platform.ai_usage:read` with its read | Streaming (section 6.6 criteria not met); scheduled abandoned-attempt job (would need a new system purpose; swept per tenant instead) |
| AI-E | Migration `b8e2d4f6a1c3`; tenant preferences (residency, retention, training use), narrowing only | Tenant-owned credentials (explicit owner decision required by this roadmap) |
| AI-F | Migration `c5d7e9f1a2b4`; immutable price versions; cost estimates with provenance; soft monthly token quota with a required-limit switch | Reconciliation from later provider reports (authority decision); ledger retention class (policy decision); hard caps (Q8) |
| AI-G | Gemini `generateContent` adapter with conformance coverage | Bedrock, Vertex AI and other capabilities (no consumer requirement; different credential models) |
| AI-H | Reference-consumer inference example and end-to-end test through the facade; consumer guide section; documentation | Moving the reference consumer's exact-SHA pin (only after commit and merge) |

### Negative controls (each weakening applied alone, its test failed, file restored byte for byte)

| Control | Result |
|---|---|
| caller authorization removed | caught |
| pre-send evidence not committed | caught |
| disabled tenant policy accepted | caught |
| installation policy and ADR-0013 gate both removed | caught |
| ADR-0013 gate always allows | caught |
| classification ceiling removed | caught |
| entitlement gate skipped | caught |
| retry after a possibly-accepted outcome | caught |
| admission slot never released | caught |
| support access may run inference | caught |
| trust entry ignores the port | caught |
| never-trustable check removed from the client | caught |
| origin change keeps the credential binding | caught |
| tenant preferences ignored | caught |
| soft quota never refuses | caught |
| facade contract removed | caught |

Defence in depth observed: removing only the routing check of installation
policy is still refused by the ADR-0013 evaluator, and removing only the
clear-on-change of a credential binding is still refused by the origin
comparison at eligibility; the controls therefore remove both layers, or
assert the stored state directly.

### Validation on the final tree

| Gate | Command | Result |
|---|---|---|
| Lint | `ruff check .` | passed |
| Format | `ruff format --check .` | passed (872 files) |
| Types | `pyright` | 0 errors |
| Import boundaries | `lint-imports` | 21 kept, 0 broken |
| Default suite | `pytest` | 4299 passed, 89 skipped (88 Caddy, 1 POSIX; pre-existing), 0 failed. Run before four comment-only `pragma: allowlist secret` additions |
| Integration | `scripts/check-integration.sh (disposable PostgreSQL 16, Redis 7)` | **Passed (run 3, 2026-10-17, final tree):** 2776 passed, 0 skipped, 0 failed, exit 0, in 49 min 52 s, started with 5.8 GB of memory free. Earlier runs, kept for the record: run 1: 2775 passed, 0 skipped, 1 failed. Run 2 (2026-10-17): 2770 passed, 5 skipped, 1 failed. Every non-pass came from the machine being critically low on memory: the scaffold test's `pip wheel` child failed to start (Windows 0xC0000142), and five Docker-backed tests skipped because Docker or ZITADEL setup did not respond. The host stopped the gate's shell both times; the test process finished on its own. Each of those 6 tests then passed in focused runs on disposable services: Redis persistence and rate-limit backend failure 6 passed; ZITADEL backup drill and consumer scaffold 2 passed |
| Migrations and reference consumer | `scripts/check-migrations.sh (disposable PostgreSQL 16, Redis 7)` | passed: graph 7, gate 7, reference consumer end to end (real wheel, isolated venv) 1 |
| Focused AI integration | `pytest -m integration (AI test files, per phase)` | passed in each phase (AI-C 549, AI-D 89 and 53, AI-E 49, AI-F 53, AI-H 2) |
| Negative controls | `scratchpad aid_negative_controls.py` | 16 of 16 caught, every file restored byte for byte |
| Dependencies | `pip-audit` | no known vulnerabilities |
| Frontend audit | `scripts/npm_audit_gate.py frontend` | passed (the accepted braces exception only) |
| Secrets | `detect-secrets-hook over tracked files and tests/architecture/test_secrets_gate.py, in a disposable clone of the exact final tree` | passed; 11 tests passed; baseline unchanged by the hook (one legitimate line shift, 149 to 154) |
| Packaging | `scripts/check-packaging.sh` | passed, 7 tests. `tests/test_wheel_contents.py` now also requires `saas_os.inference`, `saas_os.control_plane.inference` and its `adapters` and `config` packages, and `saas_os.infra.egress` in the wheel and in the isolated-install import probe. The wheel declares `httpx>=0.28.1,<0.29` and `httpcore>=1.0.9,<1.1` and contains no environment file, test or key material |
| Docker | `scripts/check-docker.sh` | passed: backend and frontend builds, health, readiness and its 503 path, worker job, no secret in logs or image history, clean shutdowns, compose config. Run locally with a scratch Compose override that removes the published host ports for `db`, `redis` and `backend`, because a native PostgreSQL holds port 5432 on this machine; the gate reaches every service from inside its containers. The image imports `saas_os.inference` and reports migration head `c5d7e9f1a2b4` |
