# Data Architecture

Status: ACCEPTED. Primary storage is PostgreSQL per `docs/ADR/0002-multi-tenancy-isolation-model.md`.

## 1. Schema Ownership

Each layer/module owns a distinct namespace. Proposed convention (schema-per-owner if the database supports schemas, otherwise a strict table-prefix convention):

- `core.*` — owned exclusively by the corresponding `core/*` module (e.g., `core.tenants`, `core.users`, `core.subscriptions`, `core.audit_log`). One Core module per table family; no two Core modules write the same table.
- `infra.*` — operational tables Infra needs directly (job queue state, migration history), where not delegated to a managed service.
- `product_<name>.*` — owned exclusively by that product (e.g., `product_dograh.calls`).
- `contracts.*` — the Product Contract registry (`docs/ARCHITECTURE.md` §9), once implemented.

**Rule**: a module may hold a foreign key into another module's schema for referential integrity (e.g., `product_dograh.calls.tenant_id → core.tenants.id`) but may never write to a table it does not own. Writes cross a schema boundary only through the owning module's API/interface — never through direct SQL from a foreign module.

## 2. Migration Ownership and Sequencing

- Each module owns its own migration set, versioned and applied independently — a Product does not need Core team sign-off to add a column to its own schema, and vice versa.
- `infra/migrations` owns the *tooling* (how migrations run, in what order, with what safety checks) but not the *content* of any module's migrations.
- Cross-schema foreign keys mean migration **ordering** matters at deploy time (a Product migration referencing `core.tenants` must run after Core's tenancy migration exists) — this ordering dependency must be explicit and checked at deploy time (mechanism to be defined in `infra/deploy`), not discovered by a failed migration in production.
- Rollback: every migration must have a documented reverse path before it is considered mergeable (detailed per-phase in `docs/IMPLEMENTATION-ROADMAP.md`); this is a process rule, not yet tooling.

## 3. Cross-Module Data Access

- No module reads another module's tables directly, even for read-only purposes. Cross-module reads happen through the owning module's published interface (an internal API call, a query method exposed by that module's package, or a subscribed event/materialized projection).
- This holds even though everything may live in a single physical database in the early phases (`docs/ARCHITECTURE-DISCOVERY.md` §11) — the discipline is what allows schemas to later move to separate physical databases without a rewrite.

## 4. Event Ownership

- The module that owns a piece of state owns the event(s) describing its changes (e.g., `core/billing` is the sole emitter of `subscription.upgraded`, `subscription.canceled`). No other module fabricates or re-emits another module's domain events.
- Event schemas are versioned. A breaking change to an event's shape follows the same discipline as an API version change (`docs/API-ARCHITECTURE.md`).
- Consumers (Product modules, AI Control Plane) subscribe to events through an explicit subscription mechanism; they do not poll owning modules' tables to infer changes.
- The event transport mechanism (in-process pub/sub vs. a message broker) is an open decision — see `docs/ADR/`. The ownership rule holds regardless of transport.

## 5. Background Job Data Ownership

- A background job's state (queue entry, execution history, retry count) is owned by `infra/jobs` as generic execution metadata.
- The *business data* a job acts on remains owned by whichever module's data it touches, accessed through that module's normal interface — a job is just a deferred/scheduled caller, not a bypass of ownership rules.

## 6. Usage/Metering Data

- `core/usage` owns the canonical usage-event store and aggregation logic. Products emit usage events through Core's ingestion interface (declared in the Product Contract's `billingMetrics`, `docs/ARCHITECTURE.md` §9) rather than maintaining their own usage counters that Core has to trust or reconcile.
- Given usage events are high-volume and append-mostly, this store may warrant a different physical storage engine than the primary transactional database (e.g., a time-series or log-oriented store) — an open decision, not fixed here, and transparent to consumers through `core/usage`'s interface either way.

## 7. Audit Log Data

- `core/audit-log` owns a single append-only, immutable store for platform-wide privileged-action history (`docs/SECURITY.md` §8). It is physically and logically separate from operational data so retention/compliance policy can differ (longer retention, no update/delete path) without affecting operational schema design.

## 8. Data Classification (Pointer)

See `docs/SECURITY.md` §9. Formal retention/classification policy is deferred until a compliance target is chosen (open human decision).

## 8.1 Tenant Data Is Not Automatically AI-Eligible Data

Per `docs/ADR/0013-ai-data-privacy-and-external-model-boundary.md` (Accepted): "tenant data," "identity data," "sensitive data," "AI-processing data," and "external-provider data" are distinct concepts, not synonyms, and must not be treated as one undifferentiated pool:

- **Tenant data** (§1, `product_<name>.*`/`core.*`) is data a module owns and may read/write per this document's ownership rules. Ownership under this document governs *internal* read/write access — it says nothing about eligibility for transmission to an *external* AI/LLM provider.
- **Identity data** (`core.users`, session/credential-adjacent records owned by `core/identity`) is treated as sensitive by default (`docs/SECURITY.md` §9) and is never assumed AI-processing-eligible.
- **Sensitive data** is any data class not yet explicitly classified and policy-approved for external AI use — the default-deny rule (`docs/SECURITY.md` §6.1, rule 3) applies regardless of which module owns it.
- **AI-processing data** is the (currently empty, policy-gated) subset of tenant/identity data that a tenant's AI data policy has explicitly permitted for a specific external-AI use case (ADR-0013 §4) — this subset does not exist as a concept in the schema today; no table or flag implements it yet.
- **External-provider data** is whatever minimal, minimized subset of AI-processing data actually crosses the AI data boundary for one request — never the full source record.

A module's ownership of a table (§1) is authorization to read/write that data internally; it is never, by itself, authorization to send that data to an external AI provider. That second authorization is the AI data boundary's alone to grant (`docs/AI-CONTROL-PLANE.md` §2.1), and is out of scope for this document beyond this pointer.

## 9. Technology Direction

**PostgreSQL is Accepted** as the primary transactional store (`docs/ADR/0002-multi-tenancy-isolation-model.md`) — relational integrity for tenancy/billing/RBAC, and native Row-Level Security backing `docs/MULTI-TENANCY.md` §2's isolation model. Object storage for files, and a secondary store for usage/audit if warranted by scale, are anticipated but not yet selected — these remain open, smaller-scoped decisions and do not require a new top-level ADR unless a genuinely different storage paradigm (e.g., a dedicated time-series store) is proposed.

## 10. What Is Hard to Change Later

The core/product schema boundary (§1, §3) is the load-bearing decision. If Product code is ever written that reaches directly into `core.*` tables (or Core reaches into `product_*.*`), the resulting coupling is expensive to unwind once data and code both depend on it. This must be enforced from the first line of Product code, not retrofitted.
