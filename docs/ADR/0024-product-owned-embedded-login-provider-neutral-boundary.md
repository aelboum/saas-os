# ADR-0024: Product-owned embedded login through a provider-neutral login boundary

Status: DRAFT — NOT ACCEPTED
Date: 2026-09-25 (drafted); reclassified 2026-09-25 by architecture review
Supersedes / Superseded by: supersedes nothing. ADR-0005 (Accepted) and ADR-0023 (Draft) are unchanged and remain authoritative.

> **Status notice (architecture review, 2026-09-25).** This document is an **unapproved alternative under investigation**. It is not the current architecture, and it authorizes no implementation.
>
> - **Current accepted architecture:** identity-provider-owned authentication, with SaaS-OS as a pure OIDC relying party (ADR-0005; `docs/SECURITY.md` §2).
> - **Decision on SaaS-OS-mediated credential authentication** (the approach described below): **NOT ACCEPTED**. See `docs/architecture/AUTHENTICATION-BOUNDARY-REVIEW.md` for the security findings: plaintext credentials in SaaS-OS, a provider bearer token in SaaS-OS, an impersonation-capable login-client credential, MFA and WebAuthn responsibility, and additional provider privileges.
> - Earlier revisions of this draft wrongly said "Accepted", and its phase notes described uncommitted prototype code as "implemented". Both are corrected below.
> - That prototype (`core/identity/embedded_login*.py`, `core/identity/zitadel_login.py`, migration `61a7ad139d7f`, and related tests and import-linter contract) was **removed without ever being committed** (2026-09-25 cleanup). It is not part of the repository's history or of any accepted architecture.
> - The research and verification material below is kept as evidence for the decision.

## Context

Products built on SaaS-OS need a login experience they own and brand, where the end user never sees or interacts with the configured identity provider.

**Current state (implemented, and the default):**

```text
Product
  ↓
SaaS-OS GET /auth/login          (login transaction: state, nonce, PKCE S256)
  ↓
browser redirect
  ↓
identity provider hosted login   (ZITADEL v1 UI, on the provider's own host)
  ↓
GET /auth/callback               (code exchange, ID-token validation, (iss, sub) mapping)
  ↓
SaaS-OS session                  (opaque, SHA-256 at rest, HttpOnly cookie)
```

`api/auth/routes.py` implements this over the `core/identity/provider.py::IdentityProvider` Protocol. That Protocol is standards OIDC only and has one implementation, `OIDCIdentityProvider`. SaaS-OS owns the application session and all authorization.

This flow cannot meet the requirement:

- the browser renders the provider's UI;
- the address bar moves to the provider's host (ADR-0023 §9);
- the provider's own browser session survives SaaS-OS logout.

ADR-0005 recorded "the platform does not … implement its own login form logic", and ADR-0023 §15 recorded the visible redirect as an accepted limitation.

The evidence base for this decision is `docs/architecture/PRODUCT-OWNED-AUTHENTICATION-ARCHITECTURE.md`. It covers the full candidate comparison, sequence diagrams, threat analysis, and the ZITADEL v4.19.0 source/proto verification.

## Options Considered

### Option A — Keep hosted OIDC redirect only (current)
- Advantages: implemented; pure OIDC; no credential ever transits SaaS-OS.
- Disadvantages: the provider UI and host are visible; the provider SSO session survives SaaS-OS logout; fails the requirement.

### Option B — Deploy the provider's own login application (ZITADEL Login V2), themed
- Advantages: no provider branding; provider-maintained.
- Disadvantages: the login UI is the provider's application, not the product's. Replacing the provider replaces the login UI. Fails "product-owned" and "provider replaceable behind the boundary".

### Option C — Server-side embedded login, completed through standard OIDC (proposed by this draft; NOT ACCEPTED)
- Advantages: the browser stays on the product origin throughout. The product owns the UI. The provider stays the credential authority. Identity still comes only from the existing, validated OIDC code exchange. The generic contract is provider-neutral. Provider session state never reaches the browser.
- Disadvantages: credentials transit SaaS-OS memory. Requires a new boundary, an adapter, endpoints, encrypted server-side handle storage, and a privileged login-client credential held by the backend.

### Option D — Provider session API only, without OIDC completion
- Advantages: somewhat simpler than C.
- Disadvantages: drops signed ID-token validation (algorithm allowlist, JWKS, `iss`/`aud`/`nonce`) in favor of a proprietary session lookup. The identity result becomes provider-proprietary (contrary to ADR-0005's migration path).

### Option E — OAuth Resource Owner Password Credentials grant
- Disadvantages: removed in OAuth 2.1 and discouraged by the OAuth 2.0 Security BCP; cannot carry interactive MFA or WebAuthn; not offered by ZITADEL for human users.

### Option F — Browser calls the provider's login API directly
- Disadvantages: not buildable. Session creation and auth-request completion require privileged login-client permissions (`session.write`, `session.link`) that cannot be given to a browser. It would also require provider CORS, expose the provider host, and put provider session tokens (usable as bearer tokens against the provider's own APIs) into JavaScript.

## Recommendation

This draft originally recommended Option C. That recommendation was **not accepted** (see the status notice).

## Decision

**Pending, and NOT ACCEPTED as of the 2026-09-25 architecture review.** The text in this section records what this draft *proposed*. It is not a decision. As proposed: SaaS-OS would support a product-owned embedded authentication flow behind a provider-neutral authentication boundary, while retaining standard OIDC as the identity-validation mechanism.

### 1. Proposed architecture (NOT ACCEPTED; not implemented)

```text
Product-branded login UI                  (product origin)
          ↓
SaaS-OS embedded authentication endpoints (api/auth, same origin)
          ↓
provider-neutral EmbeddedLoginProvider    (core/identity, generic contract)
          ↓
identity-provider adapter                 (the only provider-specific module)
          ↓
provider login/session API                (server-to-server, private network)
          ↓
OIDC authorization-code completion        (provider returns a code, never an identity)
          ↓
existing SaaS-OS OIDC validation          (unchanged)
          ↓
SaaS-OS session                           (unchanged issuance)
```

- The browser remains on the product origin for the entire login interaction. It talks only to the product's page and SaaS-OS endpoints, never to the provider host.
- SaaS-OS talks to the provider server-to-server.
- The only credential the browser ever holds is the SaaS-OS HttpOnly session cookie.

### 2. Provider neutrality

- **ZITADEL is not the SaaS-OS authentication abstraction.** SaaS-OS owns the generic boundary, and ZITADEL is the current provider behind one adapter.
- The generic contract (`EmbeddedLoginProvider`, its neutral step, handle, and error types) exposes no provider-specific concept: no provider session objects, login objects, password objects, or provider session tokens. Provider handles cross the boundary only as opaque values.
- The adapter translates the provider's mechanisms into the generic contract. It is the only module permitted to name the provider, isolated by an import-linter contract (the `core/billing/stripe_provider.py` precedent).
- **The adapter yields an OIDC authorization code, never an identity.** The identity SaaS-OS acts on always comes from validated OIDC ID-token claims, so an adapter cannot mint a SaaS-OS user identity directly.
- Products integrate only with SaaS-OS endpoints. No product code calls the provider (ADR-0023 requirement 4, unchanged).

### 3. Proposed security requirements

**Credential authority.**
- SaaS-OS does not become a second password database. It stores no password, TOTP secret, passkey credential, recovery code, or lockout state.
- The configured identity provider owns and validates all credentials.
- Credentials may transit SaaS-OS memory only during the authentication operation where the provider API requires it. They must never be persisted, logged, included in audit events, traces, metrics, or exception messages, or stored in browser storage.

**Token handling.**
- Provider login/session credentials and tokens remain server-side and are never exposed to the browser. This includes the authorization code returned by the provider's completion call, which is treated as a credential.
- Where persistence is unavoidable (a provider handle across login steps, a provider-session reference for logout), it uses the existing `core.crypto` `EncryptionService` (ADR-0019). No new secret-storage mechanism is introduced.
- The provider-side login-client credential is a least-privilege secret read through `infra.secrets` (ADR-0012) and held only by the backend.

**Identity validation.** Embedded login does not replace OIDC identity validation. The existing pipeline remains authoritative and unchanged:
- authorization-code exchange with the PKCE verifier from the existing single-use login transaction;
- ID-token signature validation against JWKS, with the RS256/ES256 allowlist;
- issuer, audience, and nonce validation;
- `(issuer, subject)` identity mapping;
- SaaS-OS session issuance.

**Requirements the implementation must satisfy.** These are architectural requirements, not yet implemented:

- State-changing embedded-auth endpoints require explicit Origin validation against the configured public origin.
- CSRF protection, including login CSRF, must be designed explicitly for the embedded endpoints. SaaS-OS has no generic CSRF framework today; the design must not assume one.
- Brute-force protection operates at both the client-address level and the account level, through the existing `infra.ratelimit`, not a second limiter. Provider lockout policies remain relevant and authoritative.
- Session fixation must be prevented. Every completed authentication receives a fresh SaaS-OS session secret.
- Logout must revoke the SaaS-OS session and terminate the linked provider authentication state.
- Account recovery must not permit account enumeration.
- Tenant isolation is unchanged. Authentication establishes identity only; tenant access still requires membership plus `core/rbac`, and no tenant or user id is accepted from the client.
- Audit and log events must be secret-free: no login name, password, code, or token.
- Provider session tokens never reach the browser.
- The passkey (WebAuthn) RP ID must match the product's registrable domain. Passkeys registered under a different RP ID, such as one enrolled through the hosted UI on the identity subdomain, will not work on the product origin.
- MFA requirements must be verified independently at the SaaS-OS boundary (for example against the validated ID token's standard `amr` claim, RFC 8176). The provider callback alone must not be assumed to prove policy compliance.

### 4. Proposed ZITADEL implementation of the boundary

Only the architecture established by the investigation is recorded here:

- The ZITADEL adapter is expected to use **ZITADEL Session API v2** for supported authentication operations: session creation and checks for password, second factors, and WebAuthn, plus session termination.
- It is expected to use **`OIDCService.CreateCallback`** to complete the OIDC authorization flow.
- Routing the authorization request to SaaS-OS uses ZITADEL's per-application `login_version.login_v2.base_uri`.
- The existing SaaS-OS OIDC validation tail consumes the resulting authorization code unchanged.
- A dedicated least-privilege login-client identity is required. The bootstrap `IAM_OWNER` credential (the Personal Access Token on the `zitadel-bootstrap` volume) must never be reused for runtime login operations.
- The login client is not provisioned by this ADR.

### 5. Phase 1 verification gates (VERIFY; not architectural facts)

The investigation marked the following ZITADEL behaviors as **VERIFY**. They are not established facts, and this ADR does not treat them as such. **Phase 1 must verify the required ZITADEL v4.19.0 behaviors against the actual pinned deployment before implementation proceeds.**

1. A server-initiated authorize request (no browser cookies) is accepted and produces a V2 auth request, and the exact shape of the redirect `Location` (including the auth-request parameter name) is known. If this fails, the investigation's fallback (one un-rendered browser 302 hop through the provider host) must be decided and recorded before proceeding.
2. The exact ZITADEL role/permission set for the login client (expected, but not verified, to be `IAM_LOGIN_CLIENT`).
3. Whether `CreateCallback` enforces the login policy's MFA requirement. Assume it does not until proven; the SaaS-OS-side MFA check (§3) is required regardless.
4. The `amr` values ZITADEL places in ID tokens for each factor.
5. Provider support for suppressing unknown-username disclosure ("ignore unknown usernames").
6. Login-name resolution and organization scoping when multiple organizations exist.

### 6. Current default and migration

- **`AUTH_LOGIN_MODE=hosted` remains the default** until the embedded implementation is fully implemented and validated. This proposal is not accepted, so no switch to an embedded mode is authorized.
- The hosted flow remains fully functional throughout: `GET /auth/login`, `/auth/callback`, `IdentityProvider`, `saas-os-local-identity` defaults, and existing tests are untouched.
- Embedded endpoints are additive and active only in embedded mode. The OIDC validation tail is shared, not forked.
- Switching is per deployment and reversible: the application's provider-side login routing plus `AUTH_LOGIN_MODE=embedded`.
- Existing users' credentials never move.
- Removing hosted mode is a separate, later decision.

### 7. Implementation phases (proposed; none authorized)

| # | Phase | State |
|---|---|---|
| 0 | Architecture / ADR | This draft (NOT ACCEPTED) |
| 1 | ZITADEL verification spike (§5 gates) | Investigation performed (evidence only) |
| 2 | Provider-neutral authentication boundary | Prototyped, then removed; not approved |
| 3 | Transaction/session storage (encrypted handles; migration) | Prototyped, then removed; not approved |
| 4 | ZITADEL adapter | Prototyped, then removed; not approved |
| 5 | Embedded password flow | Not started |
| 6 | Session integration | Not started |
| 7 | MFA/passkeys | Not started |
| 8 | Recovery | Not started |
| 9 | Security testing | Not started |
| 10 | End-to-end validation | Not started |

Each phase is independently checkpointed and audited. None is authorized to begin by this ADR alone beyond Phase 0.

**Prototype notes.** The three notes below describe **unapproved prototype code** written while this draft was mistakenly treated as accepted. That code was removed without being committed, and none of it exists in SaaS-OS. The notes are kept as a record of what was tried.

**Phase 2 prototype note (contract only).** Current state:

- **Unchanged.** Hosted OIDC (`api/auth/routes.py`, `IdentityProvider`) remains the only implemented and default login. `AUTH_LOGIN_MODE` does not exist yet; hosted is the only mode.
- **Prototyped (removed).** The provider-neutral boundary was prototyped in `core/identity/embedded_login.py`, with its error taxonomy in `core/identity/errors.py`. It defines:
  - a small base `EmbeddedLoginProvider` (`capabilities`, `start`, `complete`);
  - optional per-capability protocols (`PasswordLogin`, `PasskeyLogin`, `SecondFactorLogin`, `LoginRecovery`, `LoginTermination`), resolved through `require_capability()`, so unsupported capabilities are deterministic;
  - an `EmbeddedLoginTransaction` whose browser projection (`BrowserLoginState`) structurally rejects server-only values;
  - `AuthorizationArtifact` (code and state only; never an identity) as the sole completion output;
  - advisory-only `reported_factors`, per the Phase 1 finding that the provider's auth-request completion enforces no MFA or credential policy;
  - `EmbeddedLoginError`/`EmbeddedLoginErrorKind`, which collapse invalid-credential and locked-account outcomes publicly.

  The boundary is not wired into any route, has no persistence, and has no provider implementation.
- **Future.** The provider adapter (Phase 4, including §5 and Phase 1 refinements R1–R7), orchestration and routes (Phases 5+), and the `amr` policy check are not implemented. Embedded login is not operational, and ZITADEL is not connected to this boundary.

**Phase 3 prototype note (transaction storage and lifecycle).**

- **Prototyped (removed).** Server-side persistence of `EmbeddedLoginTransaction` in `core.embedded_login_transactions`: migration `61a7ad139d7f`, model `EmbeddedLoginTransactionRecord`, service `core/identity/embedded_login_transactions.py`. The table is global, with no `tenant_id` and no RLS, exactly like `core.login_transactions`, because it exists before any user or tenant is known.
- **Encryption.** Provider state is stored only as a `core.crypto` envelope whose associated data binds it to its own row id. It is decrypted only by the two explicitly server-only operations (load, complete) and erased as soon as the transaction becomes terminal.
- **Binding.** Every operation compares the caller's browser-binding digest in constant time before reading or writing anything. Deriving the digest stays with the future orchestration layer.
- **Lifecycle.** Expiry is enforced by every operation from the server clock, independently of cleanup. The lifecycle (ACTIVE → COMPLETED / TERMINATED / EXPIRED / FAILED, all terminal) is derived from the Phase 2 status plus `consumed_at`. Every mutation runs under `SELECT … FOR UPDATE`, so completion is single-use even under concurrency.
- **Cleanup.** `purge_expired_embedded_login_transactions()` is a repository operation only; no scheduled job is added, matching `purge_expired_login_transactions()`.
- **Phase 2 change.** The server-only value types (`ProviderLoginState` and the others) are no longer dataclasses and refuse copy, deepcopy and pickle. Before this, `dataclasses.asdict()` of a transaction copied the plaintext provider state into a plain dict.
- **Still future.** No route, adapter, or provider call exists. Embedded login is not operational, and hosted OIDC remains the only login.

**Phase 4A prototype note (ZITADEL adapter foundation).**

- **Current.** Hosted OIDC remains the only active login. No route, and no code path reachable from HTTP, uses the adapter.
- **Prototyped (removed).** `core/identity/zitadel_login.py` implemented `EmbeddedLoginProvider`, `PasswordLogin`, and `LoginTermination` against ZITADEL v4.19.0, using only Phase 1-verified behavior:
  - server-to-server authorize, with the redirect parsed and never followed;
  - Session API v2 with an explicit, bounded session lifetime (default 10 minutes, at most 30);
  - `CreateCallback`, returning only an `AuthorizationArtifact` for the unchanged `exchange_authorization_code()` / `validate_id_token()`;
  - `DeleteSession`.
- **Isolation.** A new import-linter contract forbids routes, hosted-OIDC modules, the generic contract and storage modules, and Product/Control Plane code from importing it, and `core.identity` does not export it.
- **Error mapping.** Unknown user, wrong password, and locked account all present publicly as `INVALID_CREDENTIALS`.
- **MFA.** When the provider forces MFA or the user has a second factor enrolled, the adapter returns `ADDITIONAL_FACTOR_REQUIRED`, never `AUTHENTICATED`. Reported factors remain advisory.
- **Runtime credential.** `IDENTITY_LOGIN_CLIENT_TOKEN` (via `infra.secrets`) for a dedicated role, `IAM_SAASOS_LOGIN_CLIENT`, holding exactly the Phase 1 least-privilege permission set. It is never `IAM_LOGIN_CLIENT` and never the bootstrap credential, and a missing token is a configuration error with no fallback.
- **Verification.** Verified against mocks and, outside the test suite, live against a disposable v4.19.0 instance using that custom role. The artifact from the adapter passed the existing SaaS-OS ID-token validation (`amr=["pwd"]`).
- **Deferred.**
  - embedded orchestration and routes (Phase 5);
  - browser activation and `login_v2.base_uri` configuration;
  - session linkage and the final `amr`/MFA policy (Phase 6);
  - second-factor verification and the WebAuthn ceremony (Phase 7);
  - recovery, which needs a separate `user.write` credential (Phase 8);
  - provisioning the custom role and runtime credential in deployments.

  Embedded login is not operational.

## Rejected Alternatives

> This list is the draft's original reasoning. It is superseded by the architecture review outcome: Option A (provider-owned authentication, SaaS-OS as a pure OIDC relying party) is the accepted architecture, and Option B (provider-owned Login V2) is under investigation. See `docs/architecture/AUTHENTICATION-BOUNDARY-REVIEW.md`.

- **Option A (hosted only):** fails the requirement.
- **Option B (provider's login app):** the login UI would belong to the provider, not the product.
- **Option D (session API without OIDC):** discards SaaS-OS's strongest existing identity control.
- **Option E (ROPC):** deprecated; no MFA or passkeys.
- **Option F (browser to provider API):** requires privileged credentials and provider tokens in the browser.

Full evaluation is in the investigation document, §3.

## What Would Be Difficult to Change Later

- **Passkey RP ID.** Once users enroll passkeys under the product's registrable domain, changing that domain invalidates them.
- **The "adapter yields a code, never an identity" rule.** Relaxing it later would let provider-specific code mint identities, a one-way erosion of the OIDC validation guarantee.
- **Mixed-mode users.** Once embedded mode is live for a deployment, its users no longer have provider browser sessions. Reverting to hosted mode is possible, but it re-exposes the provider UI and changes logout semantics.

## Related

- `docs/architecture/PRODUCT-OWNED-AUTHENTICATION-ARCHITECTURE.md`: the investigation and evidence base.
- ADR-0005: unchanged and authoritative (this draft proposed amending its login-form clause; not accepted).
- ADR-0023: unchanged (this draft proposed superseding its §15 note; not accepted).
- ADR-0012: secrets. ADR-0019: `core.crypto`. ADR-0020: log redaction.
- `docs/SECURITY.md` §2.
- `api/auth/routes.py`, `core/identity/provider.py`, `core/identity/oidc.py`: the current, unchanged implementation.
