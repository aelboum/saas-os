# Platform boundaries: core, optional capabilities and product features

**Status: assessment, 2026-11-01. Decides nothing.** Prepared against `main` `6fd2dfd` (v0.6.0 is `d980e73`; the only code change between them is the default refusal of `http://` webhook destinations, pull request #133). It proposes the rule SaaS OS uses to decide whether a capability belongs in the package, and applies it to what exists today. The decisions it asks for are listed in `docs/architecture/UNIVERSAL_PLATFORM_ASSESSMENT.md` section 10. Companion documents: `docs/architecture/CAPABILITY_MATRIX.md`, `docs/roadmap/PLATFORM_CAPABILITY_ROADMAP.md`.

## 1. The rule

A capability belongs in SaaS OS only when all four hold:

1. **More than one product category needs it.** A CRM, an ERP and a project-management tool would each have to build it. One consumer's need is evidence of demand, not proof of reusability.
2. **Getting it wrong is a security, tenancy, authority, audit or reliability defect**, not a product-quality issue. SaaS OS exists to make those properties hard to get wrong. A convenience that carries none of them stays in the product.
3. **It can be expressed without product vocabulary.** "Grant a newly registered permission to an existing role" is platform vocabulary. "Contact", "campaign", "pipeline", "workspace sending domain" are not.
4. **It does not force infrastructure or a dependency on a product that does not use it** (ADR-0041). An unused capability costs nothing at install, at import and at startup.

When (1) and (3) hold but (2) does not, the right answer is usually a **seam** (a stable interface or primitive the product builds on), not a feature. When (2) holds but (1) does not, the product builds it and SaaS OS documents the pattern.

## 2. The three layers

### Layer 1: Core platform (always present)

Responsibilities whose failure breaks isolation, authority or evidence for every product. A product cannot opt out of them, and they must not depend on any vendor.

| Responsibility | Where it lives today | Governing ADRs |
|---|---|---|
| Identity (OIDC relying party, sessions, invitations) | `saas_os/core/identity/` | 0005, 0023, 0025, 0046, 0049 |
| Authorization (`can()`, typed callers, RBAC, delegation, deny, support access) | `saas_os/core/rbac/`, `saas_os/core/authority/` | 0030, 0031, 0043 |
| Platform authority (installation-scoped operators) | `saas_os/core/platform_authority/` | 0045, 0050 |
| Multi-tenancy and RLS, tenant lifecycle, purge | `saas_os/core/tenancy/`, `saas_os/infra/db/` | 0002, 0016, 0022 |
| Audit (tenant and platform audit, digests) | `saas_os/core/audit_log/`, `saas_os/core/audit_digest/` | 0031, 0051, 0053 |
| Jobs, transactional outbox, idempotency | `saas_os/infra/jobs/`, `saas_os/core/outbox/`, `saas_os/core/idempotency/` | 0007, 0032, 0033, 0036 |
| Egress control (SSRF policy, pinned connections, proxy) | `saas_os/infra/egress/`, `saas_os/infra/outbound_http.py` | 0035, 0059 |
| Secrets, field encryption, transport encryption | `saas_os/infra/secrets/`, `saas_os/core/crypto/` | 0012, 0019, 0021, 0028 |
| Observability interfaces and redaction | `saas_os/infra/observability/` | 0009, 0020 |
| Rate limiting, API keys, route policy, same-origin check | `saas_os/infra/ratelimit/`, `saas_os/core/api_keys/`, `saas_os/api/` | 0030, 0034, 0044, 0047 |
| Usage ledger, feature flags, configuration | `saas_os/core/usage/`, `saas_os/core/feature_flags/`, `saas_os/core/config/` | 0037 |
| Billing foundation (parties, subscriptions, entitlements; provider-neutral) | `saas_os/core/billing/` | 0008, 0029, 0048, 0052 |

Billing is in Layer 1 because entitlements gate authorization decisions and its party model (payer, merchant, service tenant) is a tenancy question; the Stripe adapter is not (Layer 2, below).

### Layer 2: Optional platform capabilities (present only when a product turns them on)

Reusable across categories, security-relevant, but not needed by every product. Each must satisfy: explicit activation (configuration or an opt-in router or function), no import of a vendor SDK until activated, no startup failure when unconfigured, a provider-neutral interface with adapters behind it, and the same Layer 1 controls (callers, audit, egress, outbox) as everything else.

| Capability | State today | Activation today | Comment |
|---|---|---|---|
| Transactional email (outbound) | Implemented: `EmailProvider`, SMTP, Mailpit, Resend | `EMAIL_PROVIDER` (ADR-0057) | Imports no SDK; Resend uses the strict egress client. Sound shape; message model too narrow (gaps 1, 4, 5) |
| Outbound webhooks | Implemented | Product calls `subscribe()` and emits events | Sound; signing scheme and egress stack need work (assessment section 6) |
| Inbound provider events | Stripe only (ADR-0048) | Opt-in router | No provider-neutral verification primitive (gap 7) |
| Governed AI inference | Implemented (non-streaming chat) | `saas_os.inference` facade, platform configuration | Embeddings absent (gap 13) |
| Opt-in HTTP routers | Implemented | Product mounts them (ADR-0040) | Correct model for optional HTTP surface |
| Stripe billing adapter | Implemented | `saas-os[stripe]` extra, `STRIPE_API_KEY` | The model to copy: extra plus startup check (`tests/architecture/test_optional_sdk_imports.py`) |
| S3-compatible backup | Implemented | `saas-os[s3-backup]` extra | Operator tooling |
| Self-learning control plane | Implemented | Product invokes it | Large surface; out of scope here |

Candidates assessed in this round: inbound webhook verification (yes, as a primitive), inbound email (no, see section 4), email domain management (no, see section 4), embeddings (later, inside governed inference), search (no), advanced scheduling (a small Layer 1 extension, not a module).

### Layer 3: Product features (never in SaaS OS)

CRM records and contacts, marketing campaigns and audiences, sales pipelines, ERP workflows, ticketing, product-specific automation and rules engines, product-specific search and ranking, business-specific AI workflows and prompts, product UX for customer domains, mailbox and conversation threading, unsubscribe preference centres, analytics dashboards, and any frontend (ADR-0042).

## 3. Where the boundary sits, by example

The boundary is between **carrying something safely** and **deciding what it means**.

| Concern | SaaS OS (carries it safely) | Product (decides what it means) |
|---|---|---|
| Unsubscribe | An `EmailMessage` can carry `List-Unsubscribe` and `List-Unsubscribe-Post` headers, validated against injection | The unsubscribe URL, its token, the preference store, suppression lists, campaign rules |
| Threading | `In-Reply-To` and `References` carried and validated as message-id lists | Which conversation a reply belongs to, routing addresses, mailbox UI |
| Sending domains | Egress that can `GET` and `DELETE` a provider API safely; secrets; audit of who changed a tenant setting | Which workspace owns which domain, the DNS-record UX, verification polling, provider choice |
| Inbound webhooks | Signature verification (a provider-neutral scheme plus adapters), replay ledger, body caps, rate limits | What a received event does |
| Inbound email | The same verification primitive for the provider's notification; a safe `GET` to fetch the message | Parsing, attachment storage, conversation matching |
| Permission upgrades | A sanctioned, audited, additive operation and a command to run it | Which roles in its product should get which new permission |
| System actions | A typed, attributable system actor in the audit trail | Which product actions run without a member, and why |
| Retries | Jitter, caps and provider `Retry-After` hints in one place for jobs and outbox | The product's own due-row queues, if it keeps them |
| SQL | Tenant-scoped sessions, RLS, and named, single-purpose expression constructors that cannot call arbitrary database functions | Query shape, search configuration, indexes and ranking in its own tables |
| Embeddings | Governed egress, data classification, quota and evidence for the call | The vector store, chunking, ranking, retrieval UX |

## 4. Capabilities that stay out, and why

- **Email domain management (Resend Domains API).** Provider-specific in shape (Resend, Postmark, SES and SendGrid each model domains, DNS records and verification differently), one consumer, and the workflow is product UX. Once egress supports `GET` and `DELETE`, a product can call the provider's API itself through `StrictEgressClient` with the same SSRF and TLS guarantees. Revisit as an optional adapter capability (the ADR-0052 `PaymentPageProvider` pattern) when a second product, or a second provider, needs it.
- **Inbound email pipeline.** Receiving mail is a product feature (CRM, helpdesk), and parsing and storing untrusted MIME is a large attack surface with no platform-level invariant to protect. SaaS OS should supply the two reusable pieces (webhook verification, safe `GET`), not the pipeline.
- **Scheduling, batch send and tags in the email provider.** Scheduling duplicates the outbox and jobs (and moves delivery state to the provider, out of SaaS OS's at-least-once accounting); batch send breaks per-message idempotency (ADR-0036) and per-message failure classification. Tags are provider metadata, possible later as a validated pass-through.
- **A generic SQL function constructor.** `func` and `text` were removed from `saas_os.infra.db` on purpose: `func.set_config(...)` or `text("SELECT set_config(...)")` inside a tenant session rewrites `app.tenant_id` and bypasses RLS (CP-07 J-INFRA-05, PRIV-03 RA-01, `saas_os/infra/db/orm.py`), and `docs/CONSUMER-GUIDE.md` section 7 forbids products to import `sqlalchemy` outside migrations for the same reason. A generic constructor or `cast` that accepts any type name stays out. What belongs in is narrower: named, single-purpose constructors (the existing `now()`/`sum_()` pattern) for functions several product categories need, each unable to name any other function (capability matrix C20).
- **Search.** No reusable invariant beyond what RLS already gives; ranking and indexing are product decisions.

## 5. Extension points a product uses instead of forking

| Need | Extension point |
|---|---|
| Own tables, RLS | Independent migration history (ADR-0016), isolation registry, `docs/CONSUMER-GUIDE.md` section 7 |
| Own permissions | `register_permission()`; grants through `grant_permission()` |
| Own routes | Product-owned app (ADR-0017) plus `require_permission`, opt-in routers (ADR-0040) |
| Own jobs | `register_tenant_job`, `register_system_job`, `saas_os.api.worker.main(extra_functions=, extra_cron_jobs=)` (ADR-0039) |
| Own events and consumers | Outbox `append_event`, consumer idempotency (ADR-0032, 0036) |
| Own provider | Billing `provider=` argument; email `send_email(provider=)`; backup `destination=` |
| Purge participation | Purge participant registration (`docs/CONSUMER-GUIDE.md` section 11) |
| AI tools and use cases | Use-case registry (ADR-0055); tool registration (still an internal import, ledger row 987) |

Gaps in this list are themselves findings: no sanctioned path for permission upgrades (#88), no system actor for non-member actions, `system_cron` outside the public `__all__`, and the AI tool registry reached through an internal module.

## 6. Tests that keep the boundary

Already enforced: import-linter contracts and `tests/architecture/test_layer_boundaries.py` (layering), `tests/architecture/test_optional_sdk_imports.py` (no vendor SDK at import), `tests/architecture/test_public_api_snapshot.py` (public surface), `tests/test_wheel_contents.py` (packaging and extras).

Proposed, with the roadmap: a test that `import saas_os` and every `saas_os.core` package import no module outside the standard library, mandatory dependencies and the package itself; a test that the worker and API start with every optional capability unconfigured; a grep-style test that no product vocabulary (a maintained deny-list) appears in `saas_os/`.
