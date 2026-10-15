# Provider extensibility review

Status: review, 2026-10-11, commit `4fccc93` (docs/P-ROADMAP.md, P7). It changes no code and decides nothing; section 4 lists what would need a decision.

The question: can a product in its own repository substitute a provider implementation **without editing SaaS OS**?

## 1. Summary

| Seam | Interface | Shipped adapters | Consumer can substitute today? |
|---|---|---|---|
| Identity | `IdentityProvider` (Protocol) | `OIDCIdentityProvider` | **By configuration, not by class.** Any OIDC issuer; no way to supply another implementation. Deliberate. |
| Billing | `BillingProvider` (Protocol) | `StripeBillingProvider`, `FakeBillingProvider` | **Yes**, by passing `provider=` on every mutating call. Only the default is Stripe. |
| Email | `EmailProvider` (Protocol) | `SmtpEmailProvider`, `FakeEmailProvider` | **Partly.** `send_email(provider=...)` accepts one; the notification job path does not pass one and is SMTP-only. |
| Secrets | `SecretsProvider` (ABC) | `EnvFileSecretsProvider`, `EnvironmentSecretsProvider` | **No.** Selected by `ENVIRONMENT`. Deliberate (ADR-0012). |
| Backup destination | `BackupDestination` (Protocol) | `S3CompatibleBackupDestination`, `LocalBackupDestination`, `FakeBackupDestination` | **Yes** when calling the library functions; the CLI path uses the S3-compatible adapter. |

No provider name appears in any migration, table or column: billing columns are `provider`, `provider_account_ref`, `provider_price_id`, `provider_customer_ref`.

## 2. Per seam

### 2.1 Identity

- **Interface**: `saas_os/core/identity/provider.py:253-312` — `get_config`, `get_flow_endpoints`, `build_authorization_url`, `exchange_authorization_code`, `validate_id_token`.
- **Selection**: `saas_os/core/identity/oidc.py:340-349`, `get_identity_provider()`, a cached singleton that constructs `OIDCIdentityProvider` directly. `saas_os/api/auth/routes.py` calls it at two points, not through an overridable FastAPI dependency.
- **Leakage**: none functional. The adapter is generic OIDC, configured by `OIDC_ISSUER_URL` and `OIDC_CLIENT_ID`. ZITADEL appears in the separate local-development bootstrap (`saas_os/infra/local_identity/`), in documentation, and as legacy `ZITADEL_*` variable names checked only for presence.
- **Documented intent**: "deliberately not a plugin/registry framework -- exactly one configured provider per deployment" (`saas_os/core/identity/provider.py:42-44`).
- **Substitution test**: `tests/core/identity/test_identity_provider_contract.py` (a fake implementing the Protocol); the route tests substitute by monkeypatching.
- **Assessment**: adequate. OIDC is the abstraction; a product changes identity vendor by changing the issuer. A non-OIDC provider (SAML, a proprietary API) is not supported and would need a design decision, as would the embedded-login boundary in ADR-0026 (Draft).

### 2.2 Billing

- **Interface**: `saas_os/core/billing/provider.py:85-162` — `name`, `honors_idempotency_keys`, `create_subscription`, `ensure_customer`, `get_subscription_status`, `change_plan`, `cancel_subscription`.
- **Selection**: every mutating function takes `provider: BillingProvider | None = None`. The default comes from `saas_os/core/billing/service.py:180-184`, which imports and constructs the Stripe adapter lazily. In the commercial path (`saas_os/core/billing/commercial.py:256-266`) the default is used only when the merchant account's provider is `"stripe"`; any other value requires an adapter to be passed, and its `name` must equal `MerchantAccount.provider`.
- **Leakage**:
  1. the literal `"stripe"` in Core at `saas_os/core/billing/commercial.py:214,259,520` — the default-provider name;
  2. `verify_stripe_webhook_signature()` returns a `stripe.Event` (`saas_os/core/billing/stripe_provider.py:158-181`). It is inside the adapter module, but its return type is the SDK's. ADR-0008 already records this as a known violation. *(2026-10-15: ingestion, ADR-0048, uses `parse_stripe_event()`, which returns the provider-neutral `ProviderEventNotice`; the old function remains, deprecated.)*
- **SDK import**: `stripe` is imported only in the adapter, and the adapter only inside `_default_provider()`; `import saas_os.core.billing` does not load it (`tests/architecture/test_optional_sdk_imports.py`).
- **Substitution tests**: `tests/core/billing/test_commercial_parties_integration.py` (a second provider), and `FakeBillingProvider` throughout the billing and usage suites and the reference consumer's scenarios.
- **Assessment**: the best of the five. A product adds a provider by implementing the Protocol and passing it. There is no process-wide default override, so a product that never uses Stripe passes its adapter at each call site, which is explicit rather than a defect.

### 2.3 Email

- **Interface**: `saas_os/core/email/provider.py:57-69` — `send(message)`.
- **Selection**: `send_email(message, *, provider=None)`; the default is `SmtpEmailProvider` (`saas_os/core/email/service.py:76-79`). The notification job calls `send_email(message)` with no provider and first requires the SMTP configuration (`saas_os/core/notifications/service.py:264-273`).
- **Leakage**: `EmailConfig` is SMTP-shaped, and the notification path reads `default_sender` from it.
- **Assessment**: a product can send through another provider only for mail it sends itself. Platform-originated notification email is SMTP-only. In practice every transactional email service offers an SMTP relay, so this is a narrow limitation; a product that needs an HTTP API provider for notification mail cannot have it without a change here.

### 2.4 Secrets

- **Interface**: `saas_os/infra/secrets/provider.py:47-71` — `get`, `get_required`.
- **Selection**: `saas_os/infra/secrets/config.py:40-58` switches on `ENVIRONMENT`: the `.env`-file provider in development, the process-environment provider otherwise. Cached by `get_secrets_provider()`. No override.
- **Enforcement**: an import-linter contract forbids importing the concrete providers from outside `saas_os.infra.secrets`.
- **Documented intent**: ADR-0012 — a Vault or cloud secrets-manager provider is a future adapter that "touches `saas_os/infra/secrets` and deployment configuration only". That is an in-repository change by design; concrete providers are documented as not public API.
- **Assessment**: not consumer-pluggable, intentionally. The supported path for a product on any secrets manager is runtime injection into the process environment, which every such manager supports. A process-wide setter for the secrets provider would let any imported module redirect where credentials are read from; it should not be added casually.

### 2.5 Backup destination

- **Interface**: `saas_os/infra/db/backup/destination.py:78-106` — `upload`, `download`, `list_objects`, `delete_object`.
- **Selection**: the orchestrator functions accept `destination=`; the command-line path constructs `S3CompatibleBackupDestination` when off-site backup is enabled (`saas_os/infra/db/backup/orchestrator.py:550-554`).
- **Leakage**: none; the adapter takes a generic `endpoint_url`, so any S3-compatible store works.
- **SDK import**: `boto3` is imported inside the adapter's constructor.
- **Assessment**: adequate. Backup is operator tooling, fenced from application code by an import-linter contract; an operator who needs another destination calls the functions with one.

### 2.6 Adjacent seams

- `KeyProvider` (`saas_os/core/crypto/keys.py`): the default is secrets-backed, and `EncryptionService(key_provider=...)` accepts injection.
- `PullRequestProvider` (`control_plane/development/provider.py`): injected by parameter.

## 3. Findings

| # | Finding | Kind | Severity |
|---|---|---|---|
| F1 | Notification email is SMTP-only; `send_email`'s `provider` parameter is not reachable from the job path | Extensibility limit | Low |
| F2 | `"stripe"` literal in `saas_os/core/billing/commercial.py` as the default-provider name | Provider name in Core, outside the adapter | Low |
| F3 | `verify_stripe_webhook_signature()` exposes `stripe.Event` | Known (ADR-0008); resolved for ingestion by ADR-0048 (2026-10-15), the function kept and deprecated | Low |
| F4 | Identity and secrets selection are not consumer-overridable | By design (ADR-0023 wording in code, ADR-0012) | Not a defect |
| F5 | No process-wide default for billing; a non-Stripe product passes its adapter at every call | By design | Not a defect |

None is a security finding. None blocks a product that uses OIDC, Stripe or its own billing adapter, SMTP, environment-injected secrets and S3-compatible backups.

## 4. What would need a decision

Nothing here is implemented, because each item either reverses a documented choice or adds a process-global override in a security-relevant place.

1. **F1** — thread a provider through the notification job, or add a configured default-provider selector for email. Either is small; the second introduces configuration-driven class selection, which the identity and secrets seams deliberately avoid.
2. **F2 / F3** — move the default-provider name behind the adapter and return a provider-neutral event type. These belong with the provider-event ingestion work ADR-0029 already defers (Billing Foundation v2 Phase 6), not ahead of it.
3. **F4** — only if a product needs a non-OIDC identity provider or an in-process secrets-manager client. Neither need exists.

Recommendation: no change now. Revisit F1 when a product first needs non-SMTP notification mail, and F2/F3 with the deferred billing phase.
