# ADR-0054: Governed AI inference subsystem (AI Control Plane — inference)

Status: Proposed (2026-10-16). The ADR stays Proposed until its material open questions (section 12a) are resolved and acceptance is decided (Q6); recorded owner decisions do not make it Accepted. Section 12 labels every item as an approved owner decision, approved in principle, established requirement, candidate value, proposed, or open. **Implementation status (2026-10-17): Phases AI-B to AI-H are implemented on branch `feat/ai-inference`, not merged, under the owner's standing authorization (sections 8c and 8d; roadmap implementation records). Q11 was investigated and settled with evidence in AI-D (section 3a): the public interface is the thin facade `saas_os.inference`, invoked by products only. Streaming, tenant-owned credentials, provider-report reconciliation and the Bedrock and Vertex AI protocols are not implemented (section 8d). Implementation does not make this ADR Accepted (Q6).**
Date: 2026-10-16 (Phase AI-A); reconciled four times with owner decisions on 2026-10-16
Supersedes / Superseded by: — (the approved-in-principle facade boundary is noted, as not implemented, in `docs/ARCHITECTURE.md` section 2; implementing the permissions requires an amendment of [ADR-0045](0045-installation-scoped-platform-authority.md), written in the implementing phase, not now; [ADR-0035](0035-durable-webhooks-and-subscription-authority.md) is unchanged, and any webhook change is a separate decision (section 8b). Answers, for inference only, the open "model/provider" question of `docs/AI-CONTROL-PLANE.md` section 8 and `docs/PHASE-0.3-SECRETS-DECISION.md`)

Companion documents, all Phase AI-A, all proposed:

- [ADR-0055](0055-ai-data-governance-and-destination-authorization.md) — data classification, destination authorization, default deny.
- [`docs/architecture/AI-INFERENCE-THREAT-MODEL.md`](../architecture/AI-INFERENCE-THREAT-MODEL.md) — threat model, safe egress, webhook egress reuse.
- [`docs/architecture/AI-INFERENCE-CONTRACTS.md`](../architecture/AI-INFERENCE-CONTRACTS.md) — provider adapter, capability, error and consumer inference API contracts.
- [`docs/AI-INFERENCE-ROADMAP.md`](../AI-INFERENCE-ROADMAP.md) — phases AI-A to AI-H, authorization gates, Phase AI-A record.

## Reading this document

Every statement is one of these kinds, and says which:

- **Verified** — read in the code at `7ab9422` (`main`, equal to `origin/main`), with a file reference.
- **Documented, not implemented** — an ADR or document says it; the code does not do it.
- **Proposed** — this ADR's design. Not built, not tested.
- **Gap** — a known security or design gap.
- **Owner decision** — needs the repository owner.

## Context

### What the products need

Products built on SaaS OS need to call large language models: hosted ones (OpenAI, Anthropic), gateways (OpenRouter, LiteLLM), self-hosted servers (vLLM, Ollama) and an organization's own inference gateway. Without a platform capability each product writes its own vendor client. That puts provider keys in product code, sends tenant data with no platform control point, and gives each product its own usage accounting. ADR-0013 rejected exactly this ("Option C — Control-Plane-only boundary": a product calling a provider directly is "an equally real, arguably more likely, path").

### What exists today (verified)

| Area | State at `7ab9422` | Evidence |
|---|---|---|
| Model or provider client, inference, routing, agent runtime | **None.** No `anthropic`, `openai` or `litellm` import or dependency anywhere | `pyproject.toml` `dependencies`; repository-wide search |
| Data authorization gate (ADR-0013) | **Implemented as a pure decision.** Default deny; classifications `none`, `tenant_data`, `sensitive`; caller-supplied tenant and provider policies; one tenant audit row per decision; provenance re-check through the audit log. Never persisted; no production code produces a decision | `saas_os/control_plane/data_authorization/models.py:35-37`, `service.py:78-150` |
| Tool authorization (ADR-0004) | Implemented; tools may opt in to data authorization, none does | `saas_os/control_plane/orchestration/tools.py:128-130`, `service.py:249` |
| Self-learning "model selection" / "routing" | Labels on opaque adaptation rows; nothing reads them to route | `saas_os/control_plane/self_learning/adaptive/models.py:61-71` |
| `httpx` | Runtime dependency (`>=0.27`, 0.28.1 installed) | `pyproject.toml:93` |
| SSRF-hardened egress | Only in webhook delivery, private functions, in Core | `saas_os/core/webhooks/service.py:210-368, 818-861` |
| Secrets | `SecretsProvider.get/get_required`; environment or `.env`; no listing, versioning, rotation or tenant scope | `saas_os/infra/secrets/provider.py:53-73`, `providers.py` |
| Field encryption | AES-256-GCM `EncryptionService`, versioned envelope, caller AAD, manual rotation | `saas_os/core/crypto/service.py`, ADR-0019 |
| Usage ledger | `core.usage_events(tenant_id, metric, quantity, occurred_at)`; no unit, provider or model column; outbox-idempotent `ingest_event`; atomic `consume_quota` under an advisory lock; no reservation | `saas_os/core/usage/service.py:147-259, 461-588`, ADR-0037 |
| Quota limits | A missing numeric entitlement means **no limit** | `saas_os/core/usage/service.py:392-409` |
| Rate limiter | Redis fixed window, fail closed, one global configuration | `saas_os/infra/ratelimit/limiter.py`, ADR-0034 |
| Platform authority | Closed 18-member `PlatformPermission`; operation table; platform audit table; adding a permission needs a migration, an operation row and a bootstrap placement | `saas_os/core/platform_authority/permissions.py:10-47`, ADR-0045 |
| Operator commands | `saas-os-operator`, `saas_os.ops`, imported by nothing | `saas_os/ops/operator_cli.py`, ADR-0050 |
| Callers | `UserCaller`, `ServiceAccountCaller`, `SystemCaller(PROVISIONING / TENANT_PURGE / BILLING_OPERATIONS / PLATFORM_BOOTSTRAP)` | `saas_os/core/authority/caller.py:33-115` |

### Boundaries that constrain the design (verified)

- `saas_os.api` must not import `saas_os.control_plane` (import-linter "API does not depend on Products or the AI Control Plane", `pyproject.toml`). No SaaS OS route can call a Control Plane function.
- `saas_os.core` and `saas_os.infra` must not import `saas_os.control_plane` or the AI SDK list (`anthropic`, `openai`, `langchain`, …). `saas_os.infra` must not import `saas_os.core`.
- `saas_os.control_plane` may import Core and Infrastructure, but not SQLAlchemy/psycopg directly, `infra.secrets.providers`, `infra.db.backup`, `core.identity.erasure` or `saas_os.ops`.
- `saas_os.control_plane.data_authorization` must not import orchestration, approvals or AI SDKs.
- **Nothing forbids `saas_os.control_plane` outside `data_authorization`, or a product, from importing an AI SDK or calling `httpx` itself** (gap; section 10).
- `docs/ARCHITECTURE.md` section 2 lists the edges Product → Core, Product → Infrastructure, Control Plane → Core, Control Plane → Infrastructure and Control Plane → Product (through tools). **It lists no Product → Control Plane edge.** import-linter does not forbid one either (only `saas_os.core`, `saas_os.api`, `saas_os.infra` and `saas_os.contracts` are constrained).
- One SaaS OS installation is one database (ADR-0015 rule 3; ADR-0045 section 2).
- The Control Plane has no Alembic history of its own: its schemas (`control_plane`, `self_learning`) live in the single SaaS OS history (`saas_os/infra/db/migrations/env.py:6-8`, ADR-0016, ADR-0041).

## Options Considered

### Location

#### Option L1 — `saas_os.control_plane.inference` (recommended)
- Advantages: the ADR-0013 gate it must call lives in `saas_os.control_plane.data_authorization`; Core stays free of any AI concept beyond permission names (`docs/ARCHITECTURE.md` section 2 rule 5); the layer already owns `control_plane.*` tables; the API-to-Control-Plane contract keeps SaaS OS from exposing inference over HTTP by accident.
- Disadvantages: on its own, products would import the Control Plane directly, an edge the architecture document does not list. The owner rejected direct imports of the internal package (section 3); see L4 below. ADR-0041 already notes the Control Plane cannot be made optional by packaging; this adds to it.

#### Option L2 — `saas_os.core.inference`
- Advantages: products already depend on Core.
- Disadvantages: Core may not import `saas_os.control_plane`, so it could not call the existing data authorization gate without moving that gate into Core; it puts provider protocols, credentials and model metadata into Core, contrary to rule 5's intent even though `httpx` is not on the forbidden list. Rejected.

#### Option L3 — a new top-level layer (`saas_os.ai`)
- Advantages: no new edge into the Control Plane.
- Disadvantages: a fifth layer with its own contracts, its own place in ADR-0001 and ADR-0038's import contract, and it would still have to import `control_plane.data_authorization`. More architecture for no added safety. Rejected.

#### Option L4 — L1 for the implementation, plus a thin public facade `saas_os.inference` (F1; provisional internal design only, not approved as the public interface, Q11)
The implementation stays internal to the Control Plane; products import only a facade package that re-exports the supported entry points and types. Unlike L3, the facade is not a layer and holds no logic (section 3).
- Advantages: products never import a `saas_os.control_plane` module; the internal package can be reorganized without breaking consumers; one small module is the whole consumer surface, which is easy to pin with tests.
- Disadvantages: a sixth subpackage directly under `saas_os` (section 3, "Placement details still open"); the facade must be added to several existing import contracts so that it cannot become a way around them.

### Provider integration

#### Option P1 — `httpx` protocol adapters per wire protocol (recommended)
Two adapters at first: OpenAI-compatible Chat Completions and Anthropic Messages.
- Advantages: no new runtime dependency; SaaS OS controls redirects, proxies, DNS, IP pinning, timeouts and body limits on every byte, which a vendor SDK does not let it fully control; one adapter serves many OpenAI-compatible servers; matches how `GitHubPullRequestProvider` already talks to GitHub (`saas_os/control_plane/development/github_provider.py:42`).
- Disadvantages: SaaS OS owns protocol translation and must track protocol changes; server-sent-event parsing is SaaS OS code; each new protocol is an adapter to write.

#### Option P2 — vendor SDKs (`openai`, `anthropic`) as extras (ADR-0041 pattern)
- Advantages: less protocol code.
- Disadvantages: the SDKs own the HTTP client and its retry, redirect and proxy behaviour; enforcing pinned-IP egress would mean injecting a custom transport into each SDK and trusting its internals; an installed SDK makes a direct product call easier. Kept as a possible later adapter only if a protocol cannot reasonably be implemented over `httpx`.

#### Option P3 — a gateway library (LiteLLM) embedded in SaaS OS
- Rejected: a large dependency with its own routing, retries, cost tables and provider keys, i.e. a second governance layer. An operator may still run a LiteLLM *server* and register it as an OpenAI-compatible endpoint (Option P1).

### Administration surface

- **Option A1 — database-backed configuration, administered through Python operations and `saas-os-operator` (recommended).**
- **Option A2 — environment/configuration files only.** Rejected as the sole mechanism: no audited change history, no lifecycle states, a restart per change. Environment variables remain the *credential* source (section 6).
- **Option A3 — new platform HTTP routes.** Rejected for now: `saas_os.api` may not import the Control Plane, so a route needs a contract change; ADR-0045's platform router is Core-only. Nothing in the requirements needs HTTP administration.

## Recommendation

L1 for the internal implementation, with the public interface left to Q11; P1; A1; with the decisions in sections 1–11 and the decision register in section 13.

## Decision

**Pending; partly decided.** Section 12 lists exactly which items are approved owner decisions, approved in principle, or established requirements as of 2026-10-16. Everything else in sections 1–11 is the proposed design and is not accepted. Nothing is implemented.

### 1. Package and layering (proposed; the public interface is open, Q11)

```
saas_os/inference/                         (F1 facade: provisional internal design, not approved as the public interface, Q11; does not exist)
    __init__.py       re-exports run_inference(), stream_inference(), use-case registration (in-process registry, Q5; module path open, Q11),
                      the public request/result/usage types and the InferenceError hierarchy  <- the only module products import
saas_os/control_plane/inference/          (internal implementation; does not exist)
    entrypoints.py    the functions the facade re-exports
    models.py         request/response/usage/error types (no provider types)
    service.py        governance pipeline (section 4)
    policy.py         destination eligibility; calls control_plane.data_authorization
    routing.py        alias resolution, candidate ordering, fallback, circuit state
    usage.py          AI usage ledger, quota admission and settlement
    config/           provider/model/alias/trust configuration, validation, admin operations
    adapters/
        base.py       ProviderAdapter protocol, capability declarations, normalized errors
        openai_compatible.py
        anthropic_messages.py
        fake.py       deterministic fake for conformance and consumer tests
saas_os/infra/egress/                     (Phase AI-B; does not exist) safe outbound HTTP, no business concept
```

Rules (to be pinned by import-linter and architecture tests when the packages are created; the contracts are listed in section 3):

1. `saas_os.control_plane.inference.adapters` is the only package that knows a provider protocol. Nothing outside it parses a provider response.
2. Adapters import `saas_os.infra.egress` and nothing that makes a policy decision; the governance layer never builds an HTTP request.
3. The AI SDK list is forbidden for `saas_os.control_plane` outside `inference.adapters`, for `saas_os.inference` and for `products`. Only `saas_os.control_plane.inference` may import `inference.adapters`. This closes the bypass gap of section 10 inside this repository; a consumer's own code cannot be constrained by SaaS OS and is bound by documentation and review.
4. `saas_os.infra.egress` depends on neither Core nor the Control Plane; `saas_os.core.webhooks` moves onto it (threat model section 4).
5. Provider-specific types never leave an adapter (the rule ADR-0008 already applies to billing).
6. `saas_os.inference` contains no logic: it re-exports names from `saas_os.control_plane.inference.entrypoints` and `saas_os.core.authority` types only.

### 2. Separation of the provider layer from governance (proposed)

| Provider layer (adapters) | Governance layer (service) |
|---|---|
| Builds the wire request from a normalized, already-authorized request | Decides whether the request is authorized at all |
| Declares protocol capabilities; maps provider errors to normalized categories | Decides which models and destinations are eligible |
| Parses usage, provider request id, finish reason | Chooses the credential reference and checks its destination binding |
| Streams and parses events under limits given to it | Applies quota, concurrency, retry and fallback policy; attributes usage |
| Never reads configuration, policy, tenant or secrets storage | Never builds HTTP or parses provider payloads |

An adapter receives a resolved credential as an opaque value for the duration of one call and never returns, logs or stores it.

### 3. Consumer boundary and the public interface (Q11: boundary rules approved; public interface and dependency direction are an open blocker)

**Approved owner decision (2026-10-16): existing package boundaries are not weakened to accommodate the inference facade.**

- Products use a supported public interface. They never import internal Control Plane implementation modules.
- The internal inference implementation is provisionally located under `saas_os.control_plane.inference`.
- `saas_os.api` must not depend on the Control Plane, including through indirect imports.
- Caller authority comes from trusted caller objects, never from a supplied tenant identifier.
- No inference HTTP route is authorized.

**Implementation blocker.** The public consumer interface and its dependency direction are **not decided** (Q11). A consumer-facing inference API must not be implemented on an assumed dependency direction. Implementation phases that do not create the consumer interface (AI-B, AI-C) are not blocked by this. AI-D's consumer API is.

**Mandatory boundaries** (approved):

1. Products use only the supported public interface for inference.
2. Products do not import `saas_os.control_plane.inference` or any module under it. The rule concerns inference only; the existing tool-registration import is preserved (below).
3. Products receive no provider client, adapter, credential or configuration write access. No interface function returns one.
4. Caller identity comes from trusted authorization context: a `UserCaller` or `ServiceAccountCaller` (`saas_os/core/authority/caller.py`), built from authenticated request context or a tenant service account. A `SystemCaller` is refused.
5. A caller-supplied `tenant_id` is a claim. It establishes nothing until the caller is authorized at that tenant through Core's own authorization (`can()` / `authorize_caller`).
6. The public interface offers no parameter, flag or alternate function that skips authorization, classification, destination and endpoint restrictions, entitlement, concurrency limits or audit.
7. The existing `saas_os.api` restriction stays in force, including for indirect imports.
8. No HTTP route.

**Verified effect of the existing import rules.**
- The contract "API does not depend on Products or the AI Control Plane" (`pyproject.toml`, `source_modules = ["saas_os.api"]`, `forbidden_modules = ["products", "saas_os.control_plane"]`) has no `allow_indirect_imports`. In this repository only the two ADR-0045 contracts set that option.
- import-linter `forbidden` contracts are transitive by default. Any module that imports `saas_os.control_plane`, directly or indirectly, is therefore unusable from `saas_os.api`, and likewise from `saas_os.core`, `saas_os.infra` and `saas_os.contracts`.
- A product's own modules are not a source in any contract that forbids the Control Plane, so a product can import Control Plane–dependent modules from its own composition root (ADR-0017).

**Facade options examined.**

| Option | Shape | Status |
|---|---|---|
| F1 | `saas_os.inference` imports `saas_os.control_plane.inference` | **Provisional internal design only.** May remain documented. Not approved as the solution for any caller that is prohibited from importing it indirectly (every module in `saas_os.api`, `saas_os.core`, `saas_os.infra`, `saas_os.contracts`) |
| F2 | Facade imports no Control Plane module; the implementation registers itself at startup | **Not approved** (owner, 2026-10-16): it weakens the existing boundary by letting `saas_os.api` reach Control Plane behaviour indirectly |
| F3 | Facade inside `saas_os.control_plane` (for example `saas_os.control_plane.public`) | **Not approved** as the public consumer interface (owner, 2026-10-16) |

**Follow-up design investigation required** (before the consumer interface is implemented). It must establish:

1. which component invokes inference in the intended product architecture: product application code, product workers, SaaS OS routers, SaaS OS jobs, or Control Plane agents;
2. whether inference is a library capability, an internal application service, or a combination of interfaces (for example, public types plus an invocation entry point owned by the product's composition root);
3. which dependency direction preserves the existing package boundary;
4. how products invoke inference without depending on implementation details;
5. whether the design works with the existing import-linter contracts **unchanged**;
6. whether a supported Python interface meets the requirements without an HTTP route.

Import rules are not modified to make a design pass.

**Candidate approaches** (proposals only, not approved, listed so the investigation has a starting point):

- **C1 — product-only invocation.** Inference is invoked only by product code (and Control Plane agents), never by `saas_os.api`, Core or Infrastructure. F1's shape then suffices *for those callers*, and the investigation's task is to confirm that no SaaS OS layer needs to invoke inference. Trade-off: SaaS OS can never ship an inference-using router or job.
- **C2 — split types from invocation.** Request, result and error types live in a dependency-free module that any layer may import. Invocation stays in a module that imports the Control Plane and is called only from product composition code. Trade-off: two public modules; the types module must stay free of Control Plane imports, which a contract would have to pin.
- **C3 — invocation through an existing Control Plane mechanism** (for example orchestration), for callers that are themselves Control Plane agents. Trade-off: covers agents only, not products.

None of these is presented as the answer.

**Contracts that would enforce F1, if it is chosen for permitted callers** (reference only; no contract is changed now):

| Contract | Source | Forbidden | Notes |
|---|---|---|---|
| Products import inference only through the public interface | `products` | `saas_os.control_plane.inference` | `allow_indirect_imports = true` (precedent: ADR-0045's direct-import contracts) |
| Facade is thin | `saas_os.inference` | everything except the internal entry points, public types and `saas_os.core.authority` | Architecture test (import-linter has no "only" contract) |
| Adapters are private | everything except `saas_os.control_plane.inference` | `saas_os.control_plane.inference.adapters` | Direct imports |
| AI SDKs only in adapters | `saas_os.control_plane`, `saas_os.inference`, `products` | the AI SDK list | Extends the existing two AI-SDK contracts |
| Existing contracts cover the facade | add `saas_os.inference` to the `source_modules` of the SQLAlchemy, secrets-providers, backup, erasure and operator-commands contracts | — | Otherwise the facade would be an unconstrained new root |
| Consumers in this repository | `examples/reference-consumer`, `examples/consumer-scaffold` | direct `saas_os.control_plane.inference` imports | Architecture test |

A consumer's own repository cannot be constrained by SaaS OS's import-linter. There, the boundary rests on the documented public interface, on the internal package carrying no stability promise, and on review.

**Existing tool registration: preserved (owner decision, 2026-10-16).**
- The reference consumer registers an AI tool with `from saas_os.control_plane.orchestration.tools import ToolDefinition, ToolExecutionContext` (`examples/reference-consumer/reference_consumer/tools.py:25`; `ToolRegistry` and `default_registry()`, `saas_os/control_plane/orchestration/tools.py:133-194`). This is the product `aiTools` path of `docs/ARCHITECTURE.md` section 9 and `docs/AI-CONTROL-PLANE.md` section 10.
- It is an existing supported integration, intact, not migrated, and outside the inference interface rule.
- Its future public status is a separate open question (Q1).

**Placement details** (settled with whatever change creates the packages):
- A sixth subpackage directly under `saas_os` would need `tests/architecture/test_namespace_contract.py`, the explicit `[tool.setuptools] packages` list and possibly an ADR-0038 note.
- `saas_os/infra/update/policy.py` classifies unknown paths as `unknown`; new inference paths need a category and a policy-version bump.

### 3a. Q11 settlement (2026-10-17, AI-D; evidence-based, under the owner's authorization to settle it)

**Settled: C1 + F1.** AI inference is invoked by products only (C1); the public
interface is a thin facade, `saas_os/inference/__init__.py` (F1), over the
internal `saas_os.control_plane.inference`. Evidence (prototype and the
final contracts, `tests/architecture/test_ai_inference_boundaries.py`):

- A facade that imports the Control Plane cannot be imported by `saas_os.api`,
  Core or Infrastructure: the existing transitive contracts break, unchanged.
  This is the desired property, not a defect: SaaS OS itself never invokes
  inference, so no existing boundary needs weakening.
- A product importing the facade broke only the AI-B products contract,
  because that contract was transitive. It is now direct-only
  (`allow_indirect_imports = true`): a product may not import the internals
  directly, and reaches them only through the facade.
- A cycle (the internal package importing the facade) was not caught by any
  existing contract. The new contract "SaaS OS never invokes the public AI
  inference interface" forbids `saas_os.api`, `contracts`, `control_plane`,
  `core`, `infra` and `ops` from importing `saas_os.inference`, transitively.
- The facade is thin by test: it imports only the consumer-facing internal
  modules, defines no class, and its two functions each make one delegating
  call with the caller's own arguments; no runtime, adapter or configuration
  seam is exposed.
- Negative controls: each injected forbidden import breaks the intended
  contract; a product importing the facade keeps every contract.

The operator-command contract was narrowed in the same change: `saas_os.ops`
may use the configuration operations but never `…inference.adapters`
("Operator commands do not use the AI provider adapters"); the provider
capability enum moved to the neutral module `…inference.capabilities` so that
configuration code never imports an adapter.

### 4. Governance pipeline (proposed; detail in the contracts document section 5)

For each request, in this order, failing closed at each step:

1. **Caller and tenant authority.** `caller` is a `core.authority` `UserCaller` or `ServiceAccountCaller`; a `SystemCaller` is refused (no system purpose is proposed). It is authorized the way Core authorizes (`authorize_caller` / `can()`) for a new tenant RBAC permission, proposed `ai.inference:run`, at `tenant_id`. A tenant id is a claim checked by that authorization, never trusted on its own.
2. **Tenant lifecycle.** The tenant is open (`require_open_tenant`).
3. **Request validation.** Shape, sizes, use case registered, content-part classifications present and valid (ADR-0055).
4. **Alias resolution.** Alias → ordered candidates (provider, model).
5. **Candidate filtering.** Each candidate must be enabled at platform level, not past its retirement date, not circuit-open, support every requested capability, and pass destination authorization for the request's effective classification (ADR-0055).
6. **Admission.** The entitlement gate and the bounded per-tenant concurrency limit, both required in AI-D (Q12, section 7). A rejection sends no content. Soft token-quota admission is added in AI-F.
7. **Pre-send evidence, then egress.** The attempt-level decision record, the destination-level evidence and the attempt record are written before any content is sent (Q10, Q7; section 7a). If any required write fails, nothing is sent. The adapter then calls the destination through `saas_os.infra.egress` with the destination's bound credential.
8. **Settlement.** Usage recorded per attempt; result normalized; fallback only where section 8 allows.

### 5. Configuration model (proposed, Phase AI-C)

Global, platform-managed tables in the `control_plane` schema, classified `GLOBAL` with the tenant-context exclusion policy ADR-0045 uses for its global tables (`saas_os/infra/db/rls.py:60-100`), rows never deleted, every change versioned and audited in `core.platform_audit_log` in the same transaction:

| Table | Purpose | Key fields |
|---|---|---|
| `ai_providers` | A destination | `key`, `protocol` (`openai_chat_completions`, `anthropic_messages`), `base_url`, `credential_ref`, `credential_binding` (the origin the credential is bound to), `trust_entry_id` (nullable), `status` (`active`, `disabled`), `data_handling` (operator-declared retention, training-use and residency attributes; declarations, not verified facts), `version` |
| `ai_models` | A model at a provider | `provider_id`, `model_id` (the provider's identifier), declared capabilities, context window, max output tokens, `lifecycle` (`active`, `deprecated` with `retire_after`, `disabled`), `pricing_ref` (nullable) |
| `ai_aliases` | Stable product-facing name | `alias`, ordered candidates, fallback policy, required capabilities |
| `ai_endpoint_trust` | Narrow private-endpoint trust (threat model section 3.10) | exact host, port, allowed CIDRs, reason, expiry |
| `ai_platform_policy` | Installation-wide destination eligibility | provider keys eligible per classification, residency tags |
| `ai_pricing` | Versioned price table (Phase AI-F) | model, unit prices, currency, `version`, `effective_from` |

Validation at write time: protocol known; `base_url` scheme `https` (plain `http` only to a destination covered by a trust entry); host not an IP literal unless a trust entry names it; port allowed; credential reference names a secret that resolves (existence only — the value is never placed in the operation's result, audit or log); every alias candidate exists; a model cannot be `active` under a `disabled` provider.

**Implementation status (2026-10-17; branch `feat/ai-inference`, not merged).** The implementation differs from this proposed section in two ways. They are recorded here instead of rewriting the section, and section 8d records the implemented shape.

- **No tenant-context exclusion policy.**
  - Migrations `e4b8c2d6f1a3` and `c5d7e9f1a2b4` create the global tables without RLS. The governed inference path reads them inside a tenant transaction (`tenant_session_scope`), where the exclusion policy would hide them.
  - As built in AI-C and AI-F, the application role held `SELECT, INSERT, UPDATE`, with `DELETE` revoked.
  - Writes were protected by `run_platform_change` (fresh platform authorization and same-transaction platform audit), not by the database. The database did not stop code running as the application role inside a tenant transaction from writing these tables.
  - **Superseded on the branch by [ADR-0056](0056-platform-configuration-database-identity.md) (Proposed, 2026-10-17; migration `f6a2c8e4b1d9`).** The application role now only reads the six tables; a separate platform-configuration database role (`PLATFORM_CONFIG_DATABASE_URL`) is the only role that can insert or update them, and nothing can delete them. Every write still goes through `run_platform_change`, which runs the authorization, the change and the audit row on that role's connection. This is a database boundary, though not the exclusion policy this section proposed: the global tables still have no RLS, because the inference path reads them inside a tenant transaction. ADR-0056 records what it does not cover.
  - The investigation below is kept as the record of why a separate identity was needed.
  - **Investigated 2026-10-17 (before ADR-0056).** The architecture as it then stood could not provide a database-enforced platform mutation boundary.
    - There is one database principal for all application code (ADR-0045 section 9a).
    - The application role itself can write `core.platform_operators` and `core.platform_grants`, so no database-side check of platform grants can establish who the caller is.
    - `app.tenant_id` is not a credential.
    - ADR-0030 forbids `SECURITY DEFINER` functions.
    - A second database role is a separate ADR-0045 decision.
  - The options and their trade-offs are recorded in the ledger entry. The owner chose option (1), a dedicated database identity, which ADR-0056 specifies.
- **Names and columns.**
  - `ai_platform_policy` is `ai_destination_policy`: provider, classification, `allowed`, `reason`.
  - `ai_pricing` is `ai_model_prices` (Phase AI-F): per model `pricing_version`, `currency`, input, output and cached-input price per million tokens, and `effective_from`.
  - `credential_binding` is `credential_origin`.
  - `ai_providers` has no `trust_entry_id`. Trust entries are matched by exact host and port at resolution.
  - `ai_models` has no `pricing_ref`; price rows reference the model.

### 6. Credentials (proposed)

- **Platform-managed first** (D3, D11). `credential_ref` is a secret *name* resolved through `SecretsProvider.get_required` at call time inside the governance layer and handed to the adapter only. ADR-0012's AI rule holds: nothing receives a `SecretsProvider` handle; audit and logs carry the name, never the value.
- **Limitation (verified):** `SecretsProvider` is process environment only. Rotation is "change the environment and restart"; revocation is "remove the variable and disable the provider row". There is no per-tenant secret, no version and no listing. This is acceptable for platform credentials and insufficient for tenant-owned ones.
- **Endpoint binding.** A provider row stores the origin (`scheme://host:port`) its credential is bound to. Every call checks that the origin it is about to connect to equals the bound origin. Changing `base_url`'s origin is an audited operation that clears the binding; the provider cannot be used until a new binding is confirmed in a second audited operation. A hostname change therefore never silently carries the credential to a new host.
- **Tenant-owned credentials** (Phase AI-E, separate authorization): stored encrypted in a tenant-owned table with `EncryptionService`, AAD bound to `(tenant_id, provider_id, origin)`, written and rotated through tenant RBAC permissions, never readable back, usage attributed to the owning tenant, revocation immediate (row state, not environment).

**Implementation status (2026-10-17; branch `feat/ai-inference`, not merged): AI credential provisioning.** This was added after the pre-publication review found that any resolving secret name was accepted.

- **The problem.** `SecretsProvider` resolves every secret of the installation from one place: the process environment in production, plus the `.env` file in development. That includes the database URLs, `REDIS_URL`, payment, e-mail, backup and signing secrets. A name that merely resolves therefore says nothing about what the secret is for.
- **Explicit provisioning.** The deployment lists the AI provider credentials in `AI_PROVIDER_CREDENTIALS`, as comma-separated secret names (`saas_os.control_plane.inference.credentials`). Only a listed name is eligible.
  - The list is an explicit enumeration, not a naming convention.
  - It is set by whoever controls the environment (ADR-0045 tier 0).
  - A holder of `platform.ai_provider:manage` can choose among the listed names only.
  - An unset or empty list provisions nothing, and a malformed list provisions nothing.
- **Where the list is checked.**
  - When `credential_ref` is set (`create_provider`, `set_provider_credential_ref`).
  - When a binding is confirmed (`confirm_provider_binding` re-checks the stored name).
  - Every time a credential is resolved for a call (`_default_credential`). The secrets provider is never asked for an unlisted name, and an unlisted, missing or empty credential fails the call with `credential_unavailable` before any content is sent.
- **Binding.** Changing the credential name clears the origin binding, exactly as an origin change does. The provider cannot be used until a second audited `confirm_provider_binding`.
- **Audit.** The platform audit metadata records the credential *name* on create, on name change (with the previous name and `binding_cleared`) and on confirmation (with the bound origin). It never records the value.
- **What it does not do.**
  - It does not stop the deployment from listing an unrelated secret. Whoever controls the environment already holds every secret.
  - It does not change `SecretsProvider` or any of its other consumers.
  - It does not protect against code running as the application database role writing `credential_ref` and `credential_origin` directly. That is the open global-table write-protection item (section 5 implementation status; `docs/P-ROADMAP.md`).

### 7. Attempt evidence, usage and quotas (Q10, Q12 approved owner decisions; quota limits an established requirement)

**Approved owner decision (Q10, 2026-10-16): AI-D produces pre-send attempt evidence; AI-F adds durable usage reconciliation, quotas and pricing.**

**AI-D — pre-send attempt evidence.**
- Before any potentially sensitive request content is transmitted to a provider, the system establishes the required authorization and policy decision and records the required evidence of the attempt (section 7a).
- If a required authorization or policy decision fails, no content is transmitted.
- If a required audit write cannot be completed, the fail-closed behaviour applies: no content is transmitted.
- The exact record structure is designed and validated in AI-D.
- Proposed mechanism: a tenant-owned table (working name `control_plane.ai_inference_attempts`, tenant RLS) whose `started` row and decision record are committed in one PostgreSQL transaction before sending. Committed rows are durable in PostgreSQL.
- That guarantee holds only if this mechanism is chosen; this ADR does not claim durability or transactional atomicity for any mechanism not yet chosen and tested.
- AI-D also correlates provider outcomes with attempts (final state, error category, provider request id, reported usage) and integrates usage with `core.usage_events` (proposed: `ingest_event`, outbox-idempotent per ADR-0036, metrics `ai.input_tokens` / `ai.output_tokens`).

**AI-F — durable usage accounting.**
- AI-F adds:
  - reconciliation between attempts and provider outcomes;
  - actual usage accounting;
  - token quotas and their enforcement model;
  - pricing and monetary budgets;
  - handling of incomplete, failed, cancelled and ambiguous provider outcomes, including attempts left `started` by a dead process.
- AI-F is **not** the first phase that records an inference attempt. AI-D does.

**Approved owner decision (Q12, 2026-10-16): the entitlement gate and bounded per-tenant concurrency are required for the first production-capable inference release in AI-D.** AI-D must not expose a production inference path without:

1. an entitlement gate that verifies whether the caller and tenant may use the capability;
2. a bounded per-tenant concurrency mechanism;
3. explicit behaviour when the entitlement check fails;
4. explicit behaviour when concurrency capacity is exhausted;
5. tests for concurrent requests and tenant isolation;
6. operational controls and observability for these limits.

**AI-D design requirements for these controls** (established requirements; the design itself is not done):
- **Entitlement source of truth** must be identified.
  - Existing primitive (verified): `has_entitlement(tenant_id, key)` / `require_entitlement` (`saas_os/core/billing/service.py:822-849`). True only if the tenant's active subscriptions grant the key as the literal `True`; a missing key means denied.
  - Proposed: key `ai.inference`. The caller side is the tenant RBAC permission `ai.inference:run` (section 4); both must pass.
- The gate is enforced server-side, inside SaaS OS, and never relies on product-supplied claims alone.
- Missing or ambiguous entitlement information denies by default.
- **Concurrency** is enforced across all application instances, not by an uncoordinated in-process counter.
  - **Gap (verified):** SaaS OS has no distributed concurrency limiter. `saas_os/infra/ratelimit` is a fixed-window request counter (ADR-0034), which bounds requests per window, not requests in flight.
  - **Candidate only (not accepted, not implemented):** a Redis-backed per-tenant count of in-flight requests with per-request leases that expire, plus an installation-wide ceiling. Before it can be accepted, its AI-D design must cover:
    - concurrent acquisition (atomic check-and-acquire, no overshoot under races);
    - lease expiration and its relation to the operation deadline and streaming lifetime;
    - worker crashes (capacity returns when the lease expires);
    - request cancellation;
    - release and cleanup on every exit path;
    - duplicate or stale releases (a lease token, so a late release cannot free another request's slot);
    - tenant isolation of keys and counts;
    - behaviour when Redis is unavailable (fail closed, consistent with ADR-0034);
    - observability and tests.
- Tenant identity for both controls comes from the trusted authorization context (section 3), never from a supplied id alone.
- A rejected request sends no provider content.
- Capacity exhaustion produces a defined, observable result: a distinct error category, a log event, a metric labelled without tenant id, and a tenant audit row if Q7's design requires it.
- One tenant must not exhaust shared capacity without bounds.
- Entitlement is not a token quota. Quotas are a separate, AI-F concern.

**Token quotas are soft (established requirement, 2026-10-16).**
- The existing quota system does not reserve capacity atomically before an operation: `consume_quota` needs the final quantity (verified, `saas_os/core/usage/service.py:546-588`), and `check_quota` is read-only and race-unsafe. It therefore **cannot guarantee a hard token ceiling under concurrency**, and no SaaS OS document may promise one.
- Token quotas (AI-F) are soft, best-effort limits. Proposed: admission checks `used + upper_bound <= limit` under the concurrency limit; settlement records actual usage. Overshoot is bounded only by concurrency × upper bound.
- A missing numeric limit means unlimited in Core (verified, `_numeric_limit`).
- **A future hard cap needs its own explicit design**, implemented and tested, covering: atomic reservation before the provider call; concurrent requests; estimated versus actual usage; failed and cancelled requests; retries and fallback; ambiguous provider outcomes; interrupted streams; reconciliation; settlement. Not designed here (Q8).
- **Monetary budgets later.** Cost is recorded as an *estimate* with a pricing version and a provenance (`provider_reported`, `estimated`, `unknown`), never as a billed amount.

### 7a. Audit granularity and event model (Q7 approved owner decision; schema and volume are design requirements)

**Approved owner decision (Q7, 2026-10-16): one durable decision record per inference attempt, with correlated destination-level decisions where needed.** The aim is enough evidence for security review, incident investigation and usage reconciliation, without an independent durable record for every internal policy check.

Four kinds of evidence are distinguished:

| Kind | What it is | When it exists | Proposed storage (not decided) | Phase |
|---|---|---|---|---|
| 1. Attempt-level decision record | The authorization and policy outcome of one inference attempt: caller, tenant, use case, effective classification, outcome, reason | One per attempt, including denied requests that never reach a destination | Tenant audit row (`core.audit_log`, `record_in_transaction`) | AI-D |
| 2. Destination-level decision evidence | A separately identifiable decision where provider selection, fallback, classification or destination authorization requires it: which destination was authorized for which classification, under which tenant and platform policy | For each destination actually attempted; a fallback to another destination always produces new destination-level evidence, never reusing the first destination's decision | Decision id carried on the attempt record and in the attempt-level record's metadata | AI-D |
| 3. Provider-attempt and outcome evidence | The record that correlates retries, fallback, failures, cancellations and successes with provider outcomes | One per actual provider attempt | Attempt row (`control_plane.ai_inference_attempts`, working name) | AI-D |
| 4. Usage reconciliation records | Accounting evidence | Per reconciled attempt or period | AI-F design | AI-F |

**Rules:**
- Retries and fallback are correlated with the original operation (`request_id`) while each actual provider attempt stays distinguishable (`attempt_number`, destination, outcome).
- Provider attempts are never merged into one record where that would hide a destination change or prevent reliable reconciliation.
- Internal checks that do not change the outcome (for example each candidate filtered out during alias resolution) do not each produce a durable record. The outcome and the reason are recorded in the attempt-level record.
- Platform configuration changes, trust entries and platform policy produce platform audit rows in the same transaction (ADR-0045). Tenant AI policy changes produce tenant audit rows in the same transaction.

**Design requirements for AI-D (and AI-F where marked):**

| Topic | Requirement |
|---|---|
| Stable correlation identifiers | `request_id` per operation, `attempt_number` per attempt, decision ids, `client_request_id` and the existing correlation id in metadata |
| Idempotency | The usage event is appended in the attempt's finalization transaction and consumed idempotently (ADR-0036). Audit rows are not deduplicated, because each records a distinct decision or attempt |
| Durable-write failure | Fail closed before sending: no content leaves without the records of kinds 1–3 that precede sending. After a provider response, a failed finalization leaves the attempt `started` for reconciliation. Whether the caller then receives the result or an error is to be designed in AI-D and stated explicitly |
| Duplicate and ambiguous outcomes | `possibly_accepted` attempts are recorded as such, with usage `unknown` or `estimated`. A provider request id seen twice is correlated, not double-counted. Resolution is AI-F |
| Retention and access control | Audit rows: existing `SECURITY_RETAIN` class (`saas_os/core/tenancy/retention.py`) and existing readers (tenant audit through tenant RBAC; platform audit through `platform.audit:read`). Attempt rows: retention class to be decided in AI-F; tenant RLS. Cross-tenant usage reading only through `platform.ai_usage:read` (section 9) |
| Sensitive-data minimization | No prompts, completions, tool arguments or results, images, credentials, provider error bodies or content hashes in any record by default. Audit metadata also obeys `saas_os/core/audit_log/metadata.py` (forbidden keys, 8192-byte limit) |
| Expected event volume | Per attempt: one attempt-level record, one attempt row, at most one usage event. Retries and fallback multiply by the attempt count, which the retry bound caps. A volume estimate per expected workload is an AI-D design deliverable; no figure is claimed here |
| Operational monitoring and reconciliation | Metrics on attempts, denials, capacity rejections, `started` rows older than the maximum operation lifetime, and finalization failures. A reconciliation job for abandoned attempts is AI-D; full usage reconciliation is AI-F |
| Quota or concurrency refusals | Whether these produce an attempt-level record or only a log event and metric is an AI-D design decision. It must not drop evidence required by ADR-0013 invariant 7 |

### 8. Retries, health and fallback (proposed; D12)

- A request is retried on the **same** destination only for a failure that happened before the request could have been accepted (DNS failure, connection refused, TLS handshake failure) or for a status the adapter declares "not processed" with conformance-test evidence (candidates: HTTP 429; Anthropic's 529 "overloaded"). An egress refusal is a policy result and is never retried. Bounded: at most 2 retries (proposed bound), honouring `Retry-After` only up to the remaining deadline.
- **Retries and fallback share the original operation deadline** (owner decision, 2026-10-16). No retry or fallback attempt receives a fresh full deadline. If the remaining time cannot cover a further attempt, the call fails with the timeout category.
- After request bytes may have reached the provider (write completed, read timeout, connection reset after the write, any 5xx not declared "not processed"), **no retry and no fallback**, unless the destination declares an idempotency mechanism that SaaS OS uses. Neither initial protocol is assumed to offer one.
- **Fallback** to the next alias candidate only for: pre-acceptance failure, declared not-processed status, open circuit, unsupported capability found before sending. **Never** for: policy denial, authentication or authorization failure at the provider, endpoint security refusal, invalid request, quota exhaustion, cancellation, or any failure after streamed output reached the caller. Every fallback candidate passes steps 5–6 of section 4 again. Each candidate is tried at most once per request (no loops).
- **Circuit breaker** per (provider, model), state in Redis. If Redis is unavailable the request fails closed (the per-tenant concurrency limit, also in Redis, cannot be checked), consistent with ADR-0034.

### 8a. Timeout model (model established; values are candidates, not approved)

**Five distinct timeouts** (owner decision, 2026-10-16):

| Timeout | Bounds | Candidate value for evaluation |
|---|---|---|
| Connection establishment | TCP connect plus TLS handshake, per address tried | 5 s |
| Read inactivity | Longest wait for the next bytes of a response (httpx `read` timeout semantics) | 30 s |
| Total non-streaming operation | The whole call, from the start of resolution to the returned result, **including** DNS resolution, connection attempts, request write, provider processing, response read, and every retry and fallback | 120 s |
| Streaming idle | Longest gap between stream events once the stream has started | 60 s |
| Maximum streaming lifetime | The whole streaming call, including setup, retries before the first event, and the stream itself | 10 min |

**These values are candidates for evidence-based evaluation, not approved policy.** They must not be hard-coded as final. Each needs validation against:
- observed provider behaviour (time to first token and total generation time per model and output size);
- integration tests against the fake server;
- expected use cases;
- operational constraints (worker concurrency, outbox lease, connection pools).

Latency-sensitive use cases (voice, interactive completion) may need tighter limits, in particular a time-to-first-token or first-event deadline. The model allows a per-use-case value no larger than the installation's maximum (open, Q3). The write timeout (request upload) is bounded by the total deadline; whether it needs its own value is decided in AI-B.

**How the total deadline bounds the operation** (design requirement; mechanism chosen in AI-B):
- The deadline is computed once when the call starts. Every step receives the *remaining* time.
- Retries and fallback share it (section 8).
- The proposed mechanism is an asyncio cancel scope (`asyncio.timeout`, Python 3.13) around the whole operation, with httpx's per-phase timeouts set to `min(per-phase value, remaining time)`. On expiry the response and connection are closed, and the attempt is finalized `interrupted` or `failed` with the timeout category.

**Limitations of the current transport stack** (stated, not claimed solved):
- **DNS.** `socket.getaddrinfo`, and the event loop's `getaddrinfo` (which runs it in a thread), cannot be interrupted. Cancelling the awaiting task returns control on time, but the resolver thread runs to completion in the background and holds a thread-pool slot meanwhile. The deadline bounds the *caller's* wait, not the resolver's work.
- **httpx.** Its timeouts are per phase; it has no total deadline of its own. The total deadline therefore depends on cancellation of the surrounding task, which only works in async code. A synchronous client cannot be bounded this way.
- **Server bytes.** A server that sends bytes slowly but steadily never trips the read-inactivity timeout. Only the total deadline (non-streaming) or the maximum lifetime (streaming) bounds it.
- **Provider-side work.** A provider may continue processing, and bill, after SaaS OS cancels. This is why a cancelled or timed-out attempt is recorded as `possibly_accepted` with unknown or estimated usage (contracts document section 4).

The timeout model applies to **AI endpoint egress**. Webhook delivery keeps its existing behaviour, a single 10-second value per phase (`saas_os/core/webhooks/service.py:91`). Changing it is a separate decision (section 8b).

### 8b. AI endpoint egress policy, separate from webhook policy (owner decision, 2026-10-16)

**Decision.** AI provider and custom-endpoint egress policy is initially **distinct** from webhook egress policy.
- A shared egress implementation (`saas_os.infra.egress`, proposed) may supply reusable security primitives: address classification, resolve-and-validate, IP pinning with the original TLS name, redirect refusal, byte-capped reading.
- Each caller passes its own explicit, scoped policy. AI endpoint restrictions are **not** imposed on webhooks.

**AI endpoint baseline** (established design requirements):
- HTTPS on port 443 by default; other ports only through explicit, validated configuration (the provider row's `base_url`, platform-audited).
- Private or internal endpoints only through narrowly scoped, explicit trust entries (threat model 3.10); no global switch.
- Protection against DNS rebinding and address-validation bypasses (validate every resolved address, connect only to a validated one, embedded-IPv4 checks).
- Correct TLS hostname verification, with IP pinning where required.
- Redirects never followed, so a redirect cannot take a request or a credential past the policy.
- `trust_env=False`, unless a separately reviewed, explicit requirement justifies otherwise.

**Webhooks.**
- ADR-0035 accepts `http` and any port on a globally routable address today, and lists HTTPS-only as deferred. That contract is **unchanged**.
- Any change to webhook URL scheme or port behaviour, or to webhook `trust_env` or deadlines, is a **separate explicit architectural decision** (Q2).
- The extraction in AI-B must be behaviour-identical for webhooks and backed by regression tests. The compatibility and security implications of possible future webhook changes are in the threat model, section 4.4.

### 8c. AI-B implementation (2026-10-16; implemented on branch `feat/ai-inference`, not merged)

What exists, all internal:

- **`saas_os.infra.egress`** (infrastructure; imports neither Core nor the Control Plane):
  - `addresses`: the address predicate, embedded-IPv4 extraction and pinning, moved unchanged from `saas_os.core.webhooks.service`. The webhook module keeps its names as aliases, so webhook behaviour and its test seams are unchanged.
  - `StrictEgressClient` / `StrictEgressPolicy`: HTTPS only; port 443 unless the policy names another; no user information; ASCII hostnames; every resolved or literal address must be public, all-or-nothing (R1); one resolution per call, with the connection pinned to a validated address and the original hostname as TLS server name and `Host`; no redirects; `trust_env=False` with an explicit certifi trust store; identity encoding only; a byte-capped body; connect and read-inactivity timeouts capped by one total `Deadline`, shared by every address attempt.
  - `compat.require_supported_http_stack()`: refuses httpx or httpcore outside the tested ranges (R4).
- **`saas_os.control_plane.inference`** (internal, no stability promise):
  - `egress_config.ai_egress_settings()`: the provisional defaults of section 8a, configurable through `AI_EGRESS_*` environment variables (R3), plus a provisional 8 MiB response limit.
  - `adapters`: the `openai_chat_completions` and `anthropic_messages` adapters, a deterministic `FakeAdapter`, the internal adapter contract and normalized errors.

**Not implemented in AI-B, by decision or scope:**
- streaming: deferred, because safe streaming needs the idle and lifetime limits, partial-output rules and stream-usage handling of contracts section 6, which would materially expand AI-B;
- retries and fallback between providers (AI-D); the only repeated attempt in AI-B is connecting to another validated address of the same destination, before anything is sent;
- private-endpoint trust (R1, AI-C);
- any configuration storage, credential storage, permission, migration, governance, consumer interface or route.

**R4 rationale.**
- Verified in the installed httpcore 1.0.9 (`httpcore/_async/connection.py:107, 151`): the `sni_hostname` extension becomes `start_tls(server_hostname=...)`, and without it httpcore uses the URL host, here the pinned IP. A certificate issued for a name then fails verification, so if the extension were ever ignored the failure would be closed, not open.
- httpx 0.28.1 itself requires `httpcore==1.*`.
- The declared bounds are the tested lines, and `saas_os.infra.egress.compat` refuses to run outside them even when the bounds are bypassed (a hand-installed version).
- Widening a range requires the real-TLS tests (`tests/infra/egress/test_strict_egress_socket_unit.py`) to pass on the new version first.
- The lower bound of `httpx` rises from 0.27 to 0.28.1. No other dependency changes.

**Limitations (stated, not solved):**
- the event loop's `getaddrinfo` runs in a thread that cannot be interrupted: the total deadline bounds the caller's wait, not the resolver thread;
- the deadline relies on task cancellation, so it applies only to this async client;
- the 8 MiB response limit and all timeout values are provisional.

### 8d. AI-C to AI-H implementation (2026-10-17; implemented on branch `feat/ai-inference`, not merged)

**AI-C.** Migration `e4b8c2d6f1a3`: global `control_plane.ai_providers`,
`ai_models`, `ai_aliases`, `ai_endpoint_trust`, `ai_destination_policy` (no
RLS; the application role cannot delete) and tenant-owned `ai_tenant_policies`,
`ai_tenant_use_case_grants`, `ai_tenant_destination_grants` (tenant RLS). The
four configuration permissions and operations (ADR-0045 amendment of
2026-10-17). Configuration operations in `…inference.config.service`: a
credential is a secret *name* that must resolve and is never stored, returned
or audited as a value; changing a provider's origin clears its credential
binding until `confirm_provider_binding`. Private-endpoint trust is
implemented (R1's deferral closed): `TrustedEndpoint` in
`saas_os.infra.egress` admits a private address only for the exact host and
port and inside the entry's networks, all-or-nothing per resolution;
loopback, link-local, metadata, multicast, unspecified and reserved ranges can
never be trusted, also through embedded IPv4. Minimum tenant AI policy
(`…config.tenant_policy`): written only with `ai.policy:manage`, tenant
audit in the same transaction, `denied` rows on refusal, support access
excluded (`AI_SUPPORT_ACCESS_EXCLUDED_ACTIONS` in Core RBAC -- a
support-access exclusion only; `is_authority_changing` and the API-key rule are
unchanged). `saas-os-operator ai-*` (thirteen commands; abbreviations
disabled so a credential option can never be mistaken for `--credential-ref`).

**AI-D.** Migration `a7f3c91e2d48`: tenant-owned `control_plane.ai_inference_attempts`
and `platform.ai_usage:read`. `run_inference` (`…inference.service`):
authority (`ai.inference:run`, user or service account of the tenant, never
support access, `denied` audit row on refusal) → validation and
classification against the in-process use-case registry (Q5) → resolution
and eligibility, each check independent, including the ADR-0013 evaluator
(`evaluate_data_authorization`) per candidate → admission: the `ai.inference`
entitlement (fail closed), the soft token quota (AI-F), then one Redis lease
holding a tenant slot and an installation slot (`saas_os.infra.ratelimit.ConcurrencyLeases`;
atomic Lua over the Redis server clock; expiry after the deadline plus a
margin; release on every exit path; stale release a no-op; Redis unavailable
refuses) → per attempt, one transaction re-authorizes, re-evaluates the
destination against fresh configuration and commits the `started` row with
its decision before anything is sent (Q10) → settlement finalizes the row and
mirrors provider-reported usage to the usage outbox in the same transaction;
the output is returned only after it commits. Retries (at most two, only for
errors the provider declared not processed) and fallback share one deadline;
never after a possibly-accepted outcome, an authentication or endpoint
failure, or a denial. Circuit breaking is shared by all instances
(`SharedCircuitBreaker`, Redis). Abandoned attempts are swept to `abandoned`
(possibly accepted, usage unknown) per tenant at that tenant's next request;
no cross-tenant job exists, because it would need a new system purpose.
`stream_inference` refuses every request: the six release criteria of the
contracts document section 6.6 are not met.

**AI-E.** Migration `b8e2d4f6a1c3`: tenant-owned `ai_tenant_preferences`
(allowed residency, maximum provider retention, exclusion of training use),
written with `ai.policy:manage` and audited. Preferences are matched against
the operator's *declared* data handling and only ever narrow eligibility;
nothing declared fails a set requirement. **Tenant-owned credentials are not
implemented**: the roadmap makes them conditional on an explicit owner
decision, which has not been given.

**AI-F.** Migration `c5d7e9f1a2b4`: global, immutable price versions
(`ai_model_prices`), managed with `platform.ai_provider:manage`. A cost
estimate (with currency and pricing version) is stored on every attempt
whose token counts are known; it is never a billed amount. Soft token quota
from the numeric plan entitlement `ai.tokens` (monthly, UTC): refused when
recorded usage plus the request's projection exceeds it; documented as soft
(concurrent requests can overshoot). `AI_INFERENCE_TOKEN_QUOTA_REQUIRED=true`
refuses a tenant with no valid limit; unreadable configuration always
refuses. Not implemented: reconciliation from later provider usage reports
(it needs an owner decision on which authority may record usage against a
tenant), and the attempt-ledger retention class (stays `DEFERRED_POLICY`, a
policy decision).

**AI-G.** The Gemini API `generateContent` adapter (`gemini_generate_content`),
with conformance coverage. Bedrock and Vertex AI are not implemented: each
needs a different credential model (AWS SigV4, Google OAuth) and the roadmap
ties each addition to a concrete consumer requirement.

**AI-H.** `examples/reference-consumer/reference_consumer/inference.py`
calls `saas_os.inference` only; its end-to-end test runs the default runtime
(real Redis admission, real plan entitlement) with a fake provider. The
reference consumer's exact-SHA pin cannot move until the change is committed
and merged; moving it is a separate, publication-dependent step.

### 9. Platform permissions (approved in principle, 2026-10-16; implementation not authorized)

The owner approved the five permissions in principle for the AI-C design. The owner's decision used the short names `ai_config:read`, `ai_provider:manage`, `ai_endpoint_trust:manage`, `ai_policy:manage` and `ai_usage:read`. The repository's platform vocabulary is `platform.<resource>:<action>`, with `platform.` as a mandatory prefix (verified, `saas_os/core/platform_authority/permissions.py:26-47`). The full identifiers are therefore the ones below; the short names refer to the same five permissions. Resource names use `snake_case` after `platform.`, as `feature_flag` and `api_key` already do. The actions `read` and `manage` both exist (`platform.tenant:read`, `platform.authority:manage`). They do not exist in executable code and must not be added until AI-C is authorized.

| Permission | Allows | Kind |
|---|---|---|
| `platform.ai_config:read` | Read provider, model, alias, trust and platform-policy configuration (never a credential value) | Oversight |
| `platform.ai_provider:manage` | Create, change, disable providers and models; credential references and bindings; aliases | Operation |
| `platform.ai_endpoint_trust:manage` | Create and expire private-endpoint trust entries | Operation (separate because it widens network reach) |
| `platform.ai_policy:manage` | Installation-wide destination eligibility per classification | Operation |
| `platform.ai_usage:read` | Cross-tenant AI usage totals per tenant, provider and model (counts only, no content) | Oversight, data-minimized |

The brief's `platform.ai_provider:manage`, `platform.ai_policy:manage` and `platform.ai_usage:read` are kept; `platform.ai_config:read` and `platform.ai_endpoint_trust:manage` are added so that reading configuration and widening network reach are separate grants.

**Separation of responsibilities.**
- Reading configuration (`ai_config:read`) never implies changing it.
- Changing destinations and models (`ai_provider:manage`) never implies widening network reach to private addresses (`ai_endpoint_trust:manage`).
- Neither of those implies deciding which classifications may go where (`ai_policy:manage`).
- Usage oversight (`ai_usage:read`) is separate from configuration.
- No platform permission reads prompts or completions, writes a tenant's AI policy, or reads a credential value.
- Cross-tenant usage totals read from the tenant-owned ledger must use ADR-0045 section 9's oversight access path: fixed projections, one tenant scope at a time, and attempt and completion audit rows.
- The tenant-side permission for a tenant's own policy (proposed `ai.policy:manage`, ADR-0055 section 7) is a tenant RBAC permission. It is a different vocabulary from `platform.ai_policy:manage`, and neither implies the other.

**Lifecycle (approved owner decision, Q9, 2026-10-16): registration follows operation availability.**
- Existing convention (verified): `tests/core/platform_authority/test_platform_operations_unit.py` (`test_every_permission_appears_and_none_outside_the_vocabulary`) requires that the set of permissions used by `PLATFORM_OPERATIONS` equals `set(PlatformPermission)`, so a permission cannot exist without an operation.
- AI-C introduces the four configuration permissions (`platform.ai_config:read`, `platform.ai_provider:manage`, `platform.ai_endpoint_trust:manage`, `platform.ai_policy:manage`), each with its operation.
- AI-D introduces `platform.ai_usage:read` together with its usage-reading operation. No dummy operation is registered to make it available early.
- Consequence, accepted by the owner: each round is an ADR-0045 "later addition". An existing installation may need two separate `python -m saas_os.api.platform_bootstrap recover` operations, one after AI-C and one after AI-D, to create the first holder of each round's permissions (ADR-0045 section 6). That cost is preferred over exposing a permission before its operation exists.

**Implementation requires the complete existing registration process** (verified from the `permissions.py:10-18` module docstring and ADR-0045 sections 4–6). Each permission needs all of the following in the phase that registers it:

1. An **ADR-0045 amendment**: the vocabulary is closed and documented as eighteen members, with the operation inventory in section 5b.
2. A **database migration** changing the `ck_platform_grants_permission` CHECK on `core.platform_grants`, with upgrade and downgrade tests.
3. **Operation-table registration**: a row per operation in `PLATFORM_OPERATIONS` (`saas_os/core/platform_authority/operations.py`) with its permission, accepted system purposes (none proposed) and platform audit action. The unit test comparing the table to ADR-0045 section 5b is updated with it.
4. **Bootstrap placement**: each member placed in exactly one of `BOOTSTRAP_PERMISSIONS` or `NOT_GRANTED_AT_BOOTSTRAP` (`saas_os/api/platform_bootstrap.py`). The disjoint-and-complete test and the pinned copy of the tuple are updated. Recommendation for AI-C review: `BOOTSTRAP_PERMISSIONS`, so a new deployment's first owner can grant them; anti-amplification would otherwise make them ungrantable.
5. **Recovery for existing installations**: an existing deployment's owners do not receive a new permission. The first holder there is created with `python -m saas_os.api.platform_bootstrap recover`, explicitly and audited, and it is granted like any other from then on (ADR-0045 section 6, "Later additions"). The AI-C runbook entry must say so.
6. **Authorization and migration tests**: for each operation, authorized, refused without the permission, refused for a `ServiceAccountCaller`, refused for every system purpose, audited in the same transaction, and a refusal leaves no change. Plus migration upgrade and downgrade. The approved direct importers of `saas_os.core.platform_authority` (`tests/architecture/test_platform_authority_contract.py:131`) gain the inference configuration module.

Core would hold five permission names and operation rows that mention AI; it would import nothing AI-related. The five permissions are approved in principle, subject to consistency with this model. If an implementing phase finds an inconsistency, it reports it rather than changing the model. Nothing in this section is implemented.

### 10. Known gaps this design must close before inference is usable (verified)

1. AI-B added import contracts forbidding the AI SDK list for the whole Control Plane and for `products`, and forbidding products and other Control Plane packages from importing `saas_os.control_plane.inference`. A raw `httpx` call elsewhere in SaaS OS is still not forbidden by a contract, and a consumer's own code cannot be constrained by SaaS OS.
2. `authorize_data_access` records with `ActorType.USER` only and writes in its own transaction; inference needs a caller-typed, same-transaction variant (ADR-0055 section 6).
3. No persisted tenant AI data policy or provider eligibility store exists; the gate denies every request until one exists (ADR-0055 section 7).
4. Webhook egress gaps (`trust_env` default, no port policy, no overall deadline, blocking DNS in async code, no bounded response reader) — threat model section 4. AI endpoint egress gets its own stricter policy (section 8b). Webhook behaviour is unchanged unless the owner decides otherwise (Q2). Nothing has changed in code.
5. `docs/AI-CONTROL-PLANE.md` line 3 says no Self-Learning runtime code exists; it does. Recorded in the deferred ledger, not fixed here.

### 11. Phased delivery (proposed)

Phases AI-A to AI-H in `docs/AI-INFERENCE-ROADMAP.md`, each separately authorized. The "AI-" prefix avoids collision with ADR-0045's Phases B–F. Only AI-A (this document set) and its reconciliations have been authorized.
- AI-C establishes the minimum tenant AI policy that AI-D requires; AI-D never assumes one exists.
- AI-D produces pre-send attempt evidence and requires the entitlement gate and bounded concurrency.
- AI-D's consumer-facing interface waits for Q11.
- AI-E extends tenant configuration and adds tenant-owned credentials, if approved.
- AI-F adds durable usage reconciliation, soft quotas and pricing.

### 12. Decision status (fourth reconciliation, 2026-10-16)

This ADR stays **Proposed**. Recorded owner decisions do not make it Accepted (Q6). Every item below carries exactly one label:

- **Approved owner decision**: decided by the owner. Implementation still needs its phase's own authorization.
- **Approved in principle**: the owner approved the direction; details remain to be designed.
- **Established requirement**: a design requirement, binding on the implementing phase.
- **Candidate value**: a number for evidence-based evaluation, not policy.
- **Proposed**: this ADR's design, not approved.
- **Open owner decision**: a question still to be answered (section 12a).

#### 12.1 Approved owner decisions

| ID | Decision | Section |
|---|---|---|
| Q11 (partial) | Existing package boundaries are not weakened for the facade. F2 not approved. F3 not approved as the public interface. F1 kept only as a provisional internal design, not approved for callers that may not import it indirectly. The public interface and dependency direction remain open and **block the consumer-facing inference API** | 3 |
| Tool registration | `saas_os.control_plane.orchestration.tools` stays an intact, supported integration, outside the inference interface rule | 3 |
| Q9 | Permission registration split by operation availability: four configuration permissions in AI-C, `platform.ai_usage:read` in AI-D with its usage-reading operation; no dummy operation; two `platform_bootstrap recover` steps for existing installations accepted | 9 |
| Q10 | AI-D produces pre-send attempt evidence; AI-F adds durable usage reconciliation, quotas and pricing; AI-F is not the first phase to record an attempt | 7 |
| Q12 | Entitlement gate and bounded per-tenant concurrency are required for the first production-capable inference release in AI-D | 7 |
| Q7 | One durable decision record per inference attempt, with correlated destination-level decisions where needed | 7a |
| Q5 | Use-case registration: an in-process registry of immutable, application-defined use cases; no persistent registry table without a demonstrated requirement for independently managed registrations; registration alone authorizes nothing; criteria for revisiting recorded | ADR-0055 section 4 |
| R1 | AI-B rejects every non-public AI destination (loopback, private, link-local, multicast, reserved, and other non-global addresses, literal or resolved). Private-endpoint trust is deferred to AI-C; no trust entry or administration exists in AI-B | Roadmap AI-B; threat model 3.10 |
| R2 | AI-B may add internal provider adapters; they are not a consumer-facing inference API, `saas_os.inference` is not created, and the risk of internal adapters reaching `main` before governed inference exists is accepted for this phase. Does not resolve Q11 | Section 3; roadmap AI-B; `docs/P-ROADMAP.md` ledger |
| R3 | The timeout candidates are configurable provisional defaults in AI-B; final values are decided and validated before AI-D (Q3) | Section 8a |
| R4 | The HTTP stack is bounded to tested versions (`httpx>=0.28.1,<0.29`, `httpcore>=1.0.9,<1.1`) and a run-time guard refuses others, because IP pinning relies on httpcore's `sni_hostname` extension | Section 8c |
| AI egress separation | AI endpoint egress policy distinct from webhook policy; ADR-0035 and webhook behaviour unchanged | 8b |
| ADR status | ADR-0054 and ADR-0055 stay Proposed until their material issues are resolved and acceptance is decided | this section |

#### 12.2 Approved in principle

| Item | Content | Section |
|---|---|---|
| Public consumer interface | Products use a supported public interface (provisionally `saas_os.inference`); trusted callers only; `tenant_id` alone grants nothing; no inference HTTP route | 3 |
| Five platform permissions | `platform.ai_config:read`, `platform.ai_provider:manage`, `platform.ai_endpoint_trust:manage`, `platform.ai_policy:manage`, `platform.ai_usage:read`, through the full ADR-0045 process | 9 |
| Classification trust model | Product-declared classifications bounded by registered use cases, tenant authorization and destination policy; labels are not verified | ADR-0055 section 4 |
| Phase sequencing | AI-A to AI-H; minimum tenant policy in AI-C; every phase separately authorized | 11; roadmap |

#### 12.3 Established requirements

| Item | Content | Section |
|---|---|---|
| AI endpoint egress baseline | HTTPS/443 default; explicit validated ports; narrow private trust; DNS-rebinding and validation-bypass protection; TLS hostname verification; IP pinning where required; redirects cannot bypass policy; `trust_env=False` by default; bounded deadlines; webhook compatibility and regression tests | 8b; threat model 3, 4 |
| Timeout model | Five distinct timeouts; deadline propagation and cancellation; DNS limitation stated; retries and fallback share the original deadline; streaming and latency-sensitive use cases considered | 8, 8a |
| Soft token quotas | No hard ceiling promised; any hard cap needs an explicit reservation design | 7 |
| Entitlement and concurrency design requirements | Source of truth identified; server-side; deny on missing or ambiguous; cluster-wide concurrency; trusted tenant identity; no content on rejection; observable exhaustion; bounded shared capacity | 7 |
| Audit design requirements | Correlation, idempotency, write-failure behaviour, ambiguous outcomes, retention and access, minimization, volume estimate, monitoring | 7a |
| Use-case authorization rules | Eight independent checks beyond registration; hold for the in-process registry and any future registry | ADR-0055 section 4 |

#### 12.4 Candidate values

| Item | Values | Section |
|---|---|---|
| Timeouts | Connect 5 s; read inactivity 30 s; total non-streaming 120 s; streaming idle 60 s; maximum streaming lifetime 10 min | 8a |
| Retry bound | At most 2 retries per destination | 8 |

#### 12.5 Proposed (not approved)

Everything else in sections 1–11, in particular:
- the package layout of section 1;
- F1 as an internal design and candidate approaches C1–C3 (section 3);
- the configuration tables (section 5) and credential binding (section 6);
- the attempt-record mechanism and its storage (sections 7, 7a);
- the Redis lease design for concurrency (section 7);
- retry and fallback eligibility (section 8);
- streaming as a separate release gate inside AI-D (contracts document section 6.6).

### 12a. Open owner decisions

| # | Question | Consequence while open | Needed by |
|---|---|---|---|
| Q11 | What public inference interface and dependency direction preserve the existing boundary (follow-up investigation, section 3) | **Settled 2026-10-17 in AI-D** (section 3a: C1 + F1, with evidence and contracts). Kept in this table for history | -- |
| Q1 | Should the existing tool-registration integration eventually receive a public consumer interface? | Products keep importing a Control Plane module for tools | Separate decision; no phase |
| Q2 | Should existing webhook scheme or port behaviour change? Requires an ADR-0035 amendment | Webhook gaps remain as recorded in the ledger | Separate decision; no phase |
| Q3 | Final timeout values after provider and workload validation, including per-use-case limits for voice | Candidates stay candidates | AI-B (egress), AI-D (inference) |
| Q6 | When ADR-0054 and ADR-0055 are accepted | Both stay Proposed | After Q11 at least |
| Q8 | What design, if any, enables reliable hard token caps | Quotas stay soft | AI-F |

Q5, Q7, Q9, Q10 and Q12 were decided on 2026-10-16 (section 12.1). R1–R4, from the AI-B readiness review, were approved by the owner on 2026-10-16 (section 12.1). Their remaining design work is listed as AI-D or AI-F requirements, not as open owner decisions.

### 13. Decision register

Status labels as in section 12.

| ID | Area | Decision | Status | Rationale (short) |
|---|---|---|---|---|
| D1 | Package location | Internal implementation provisionally `saas_os.control_plane.inference`; adapters in `…inference.adapters`; shared egress primitives in `saas_os.infra.egress`; public interface undecided | Boundary rules **approved owner decision**; public interface and dependency direction **open owner decision** (Q11, blocker for the consumer API); placement details proposed | Must call `control_plane.data_authorization`; `saas_os.api`, Core and Infrastructure may not reach the Control Plane, even indirectly |
| D2 | Provider integration | `httpx` protocol adapters: OpenAI-compatible Chat Completions and Anthropic Messages first; an SDK only as an ADR-0041 extra if needed | **Proposed** (adapters are scheduled in the approved-in-principle phase plan) | SDKs own retries, redirects and proxies; `httpx` is already a dependency |
| D3 | Platform credentials | Secret references resolved through `SecretsProvider`, bound to one origin | **Proposed**, with the stated rotation and revocation limitation | ADR-0012/0013 |
| D4 | Provider/model administration | Database-backed configuration, Python operations and `saas-os-operator`, platform-audited | **Proposed**; its permissions **approved in principle**; registration split **approved owner decision** (Q9) | ADR-0050 pattern |
| D5 | Product boundary | One SaaS OS installation and database per product | **Established requirement** (ADR-0015 rule 3, accepted) | ADR-0015; ADR-0045 section 2 |
| D6 | Consumer integration | Supported Python interface; no inference HTTP route | No route and boundary rules **approved owner decision**; interface **open** (Q11) | `saas_os.api` may not reach the Control Plane |
| D7 | Usage accounting | AI-D pre-send attempt evidence and usage integration; AI-F reconciliation, quotas, pricing; soft quotas only | Split **approved owner decision** (Q10); soft quotas **established requirement**; hard caps **open** (Q8); record structure proposed | ADR-0037 keeps `core.usage_events` as the single quota ledger |
| D8 | Data policy | Classification on every content part, use-case ceilings, tenant authorization, destination policy, deny by default | Trust model **approved in principle**; rules **established requirement**; registration model **approved owner decision** (Q5: in-process registry of immutable, application-defined use cases) | ADR-0013 |
| D9 | Private endpoints | Narrow, explicit trust; no global switch | **Established requirement**; entry shape proposed | Webhook egress has no trust mechanism (verified) |
| D10 | Administration permissions | Five platform permissions | **Approved in principle**; registration rounds **approved owner decision** (Q9); not implemented | ADR-0045 closed vocabulary; every permission needs its operation |
| D11 | Tenant-owned credentials | AI-E | **Approved in principle** (phase plan); design proposed | `SecretsProvider` has no tenant scope |
| D12 | Retries | No retry or fallback after possible acceptance; bounded pre-acceptance retries sharing the original deadline | Deadline sharing **established requirement**; eligibility **proposed**; bound **candidate value** | No idempotency keys assumed |
| D13 | Entitlement and concurrency | Entitlement gate and bounded per-tenant concurrency in AI-D | **Approved owner decision** (Q12); design proposed; distributed concurrency limiter is a verified gap | Section 7 |
| D14 | Audit granularity | One durable decision record per attempt, plus destination-level evidence where needed | **Approved owner decision** (Q7); schema and volume are AI-D design requirements | Section 7a |

Principal decisions of the Phase AI-A brief:

| Brief item | Decision | Status |
|---|---|---|
| Initial provider support | Two protocol adapters; explicit capability metadata; others in AI-G | Proposed; scheduled in the phase plan |
| Streaming | Released only when its security and operational requirements are met | Approved in principle; release criteria proposed |
| Usage, quotas, budgets | Pre-send evidence in AI-D; soft token quotas, reconciliation and pricing in AI-F; hard caps only after a reservation design | Approved owner decision (Q10); soft quotas established; hard caps open |
| External transmission | Default deny; classification on every content part; `none` is not a licence to transmit | Approved in principle |
| Credential ownership | Platform-managed first; tenant-owned in AI-E | Approved in principle |

## What Would Be Difficult to Change Later

- The consumer API (`run_inference` / `stream_inference`, result and error types). Products will pin to it; changes become breaking.
- The facade's package name (`saas_os.inference`) and the Product → facade edge once products use them.
- Platform permission identifiers, once a deployment has granted them (grants are rows, never deleted).
- Ledger semantics (attempt rows, provenance values) once usage is reported to customers.
- Any precedent of a product calling a provider directly "for now" (ADR-0013, "What Would Be Difficult to Change Later").

## Related

ADR-0001, ADR-0004, ADR-0008, ADR-0012, ADR-0013, ADR-0014, ADR-0015, ADR-0016, ADR-0017, ADR-0019, ADR-0020, ADR-0031, ADR-0034, ADR-0035, ADR-0036, ADR-0037, ADR-0041, ADR-0045, ADR-0050; `docs/AI-CONTROL-PLANE.md`; `docs/SECURITY.md` section 6.1.
