# Product-Owned Authentication — Architecture Investigation

> **Status notice (architecture review, 2026-09-25).** This investigation explored **SaaS-OS-mediated credential authentication** through the provider Session API. That approach is **NOT ACCEPTED**, and ADR-0026 is **DRAFT — NOT ACCEPTED**.
>
> - The accepted architecture remains provider-owned authentication with SaaS-OS as a pure OIDC relying party (ADR-0005).
> - Where §12–§13 below say "implemented" or "approved", they refer to an **unapproved prototype**, since removed without ever being committed, and to a draft that was mistakenly treated as accepted. None of that code exists in SaaS-OS.
> - The ZITADEL v4.19.0 behavior recorded here (§12) is kept as factual evidence.
> - The follow-up investigation of provider-owned branded login is in `docs/architecture/AUTHENTICATION-BOUNDARY-REVIEW.md` §10.

**Status:** Investigation / design only. Not a decision. Nothing here is
implemented, and nothing here authorizes implementation. This document is the
evidence base for a future ADR (§10), the same way
`SAAS-OS-DISTRIBUTION-ARCHITECTURE.md` was the evidence base for ADR-0015.

**Question:** Can SaaS-OS give a product a login page it owns and brands, where
the end user never sees or interacts with the configured identity provider,
without SaaS-OS becoming a credential store and without coupling SaaS-OS or
products to ZITADEL?

**Phase 1 update (verification spike):** every item marked **VERIFY** below
has been resolved. Most were verified live against a disposable ZITADEL
v4.19.0. Some earlier statements here are contradicted by the evidence and are
superseded by §12, which also lists the refinements implementation must adopt.
The sections below are left as originally written.

**Short answer:** Yes. The chosen design is a *server-side embedded login*
("backend-for-frontend"). The product page talks only to SaaS-OS on the
product's own origin. SaaS-OS drives the provider's supported login-client
API server-to-server. The login still ends in the standard OIDC
authorization-code exchange and ID-token validation SaaS-OS already performs.
Credentials pass through SaaS-OS in memory but are never stored there; the
provider remains the credential authority.

---

## 1. Current architecture (as implemented)

Verified against the code, not filenames.

### 1.1 Flow

```text
Browser                     SaaS-OS (saas_os/api/auth, saas_os/core/identity)           ZITADEL
   │ GET /auth/login                 │                                        │
   │────────────────────────────────▶│ begin_login_transaction()              │
   │                                 │   state, nonce, PKCE verifier (DB row) │
   │◀── 303 authorization_endpoint ──│   + HttpOnly tx cookie (10 min)        │
   │ GET /oauth/v2/authorize ────────────────────────────────────────────────▶│
   │◀──────────────── ZITADEL-hosted login UI (password, MFA, passkey) ───────│  ← user sees IdP
   │ ... credentials submitted to ZITADEL ───────────────────────────────────▶│
   │◀──────────────── 302 OIDC_REDIRECT_URI?code&state ───────────────────────│
   │ GET /auth/callback?code&state ─▶│ consume_login_transaction() (single use)│
   │                                 │ exchange_authorization_code() ────────▶│ token endpoint
   │                                 │ validate_id_token() (RS256/ES256, iss,  │
   │                                 │   aud, exp, sub, nonce; JWKS)           │
   │                                 │ get_or_create_user_for_external_identity(iss, sub)
   │                                 │ issue_session() (256-bit, SHA-256 at rest)
   │◀── 303 AUTH_POST_LOGIN_PATH ────│ Set-Cookie session (HttpOnly, Secure, SameSite=Lax)
```

- **Routes:** `saas_os/api/auth/routes.py`: `GET /auth/login`, `GET /auth/callback`,
  `POST /auth/logout` (revokes the SaaS-OS session only), `GET /auth/me`.
- **Provider boundary:** `saas_os/core/identity/provider.py::IdentityProvider`
  (Protocol with five operations). `saas_os/core/identity/oidc.py::OIDCIdentityProvider`
  is the only implementation and is pure standards OIDC (discovery, PKCE S256,
  code exchange, JWKS validation). No ZITADEL-specific code exists in
  `saas_os/core/identity` or `saas_os/api/auth`.
- **Configuration:** provider-neutral `OIDC_ISSUER_URL` / `OIDC_CLIENT_ID` /
  `OIDC_CLIENT_SECRET` through `saas_os.infra.secrets`, plus `OIDC_REDIRECT_URI`
  (`saas_os/api/auth/config.py`).
- **Session ownership:** SaaS-OS owns the application session
  (`core.sessions`, hashed; header or cookie, `saas_os/api/dependencies.py`). The ID
  token is not persisted, and there is no refresh token.
- **Identity key:** `(issuer, subject)` to `core.external_identities`. Email is
  never the key.
- **Authorization:** entirely `saas_os/core/rbac` plus tenant membership. Login
  establishes identity only.
- **Rate limiting:** `saas_os.infra.ratelimit.enforce_rate_limit`, keyed
  `auth:<client address>` (trusted-proxy aware), fail-closed.
- **CSRF:** `state` (single-use, cookie-bound) for the callback; `SameSite=Lax`
  plus POST for logout. There is no CSRF framework and no CORS middleware;
  Caddy serves the frontend and `/auth/*` from one origin.
- **Audit:** structured log events (`auth_login_*`). `saas_os.core.audit_log` requires
  a tenant, so pre-tenant auth events are not in the audit table (documented
  limitation).
- **Frontend:** no auth UI exists yet (`frontend/app/page.tsx` placeholder).
- **ZITADEL (local and production):** v4.19.0, `start-from-init`, with
  `LOGINV2_REQUIRED=false`, so the bundled v1 hosted login UI is used. The
  app is created by `saas-os-local-identity` as a public PKCE client. In
  production, ZITADEL sits on an operator subdomain (`id.example.com`, ADR-0023
  §9).

### 1.2 Existing decisions this requirement touches

| Source | Current statement |
|---|---|
| ADR-0005, Decision | "The platform does not store passwords **or implement its own login form logic** — it redirects to ZITADEL's OIDC flow." |
| `docs/SECURITY.md` §2 | "The platform does not implement its own login form, password storage, or MFA logic." |
| ADR-0023 §9 | Browser address bar changes host during the OIDC redirect; "invisible" is explicitly defined as *not* hiding the redirect. |
| ADR-0023 §15 | A "true zero browser visibility" design "would require a fundamentally different authentication mechanism." |
| ADR-0023 §14 | Non-goals: no custom authentication protocol, no custom password store, no ZITADEL SDK, no refresh-token persistence. |
| `IdentityProvider` docstring | Deliberately excludes password management, MFA, and provider-side logout. |

The new requirement reverses the "no own login form" clause of ADR-0005 and
`SECURITY.md` §2, and resolves ADR-0023 §15's limitation. It does **not**
conflict with "no password store", "no custom protocol", "no SDK", or
"SaaS-OS owns sessions/authorization".

---

## 2. Requirement gap

Requirement: *the user must never know the identity provider exists.*

The current flow fails it in three observable ways:

1. **Rendered UI.** The browser renders ZITADEL's login pages. Even branded,
   they are the provider's UI, served from the provider's host.
2. **Host change.** The address bar moves from `app.example.com` to
   `id.example.com` (ADR-0023 §9; a ZITADEL path-prefix deployment is
   unsupported).
3. **Provider-side browser state.** ZITADEL sets its own session cookies on
   its own host. Logout (`POST /auth/logout`) revokes only the SaaS-OS session,
   so the provider SSO session survives, and the user can be silently re-logged
   in or shown a provider "select account" page.

Branding the hosted UI (label policy, custom domain) reduces item 1 but cannot
remove items 1 to 3. The gap is structural: in redirect-based OIDC, the
*browser* is the channel between relying party and provider.

---

## 3. Candidate architectures

Facts about ZITADEL below were verified against ZITADEL **v4.19.0** source and
protos (the pinned image): `proto/zitadel/session/v2/session_service.proto`,
`proto/zitadel/oidc/v2/oidc_service.proto`,
`proto/zitadel/session/v2/challenge.proto`,
`proto/zitadel/application/v2/{login,oidc,application_service}.proto`,
`proto/zitadel/user/v2/user_service.proto`, and
`internal/api/oidc/auth_request.go`. (zitadel.com docs were unreachable from
this environment; where a behavior is inferred rather than read from source,
it is marked **VERIFY** and becomes a gate in §9.)

| | A. Hosted OIDC redirect (current) | B. ZITADEL Login V2 app, self-hosted and themed | C. Server-side embedded login + OIDC completion | D. Session API only, no OIDC | E. OAuth ROPC password grant | F. Browser calls IdP API directly |
|---|---|---|---|---|---|---|
| **What renders login** | ZITADEL v1 UI | ZITADEL's Next.js login app | Product page | Product page | Product page | Product page |
| **Browser talks to** | Product and IdP host | Product and login app (IdP code) | Product origin only | Product origin only | Product origin only | Product and IdP API (CORS) |
| **User sees IdP** | Yes (UI and host) | No branding; IdP-built app | No | No | No | IdP host visible in network traffic |
| **Credentials submitted to** | IdP | Login app, which calls IdP | SaaS-OS (in transit), then IdP | SaaS-OS, then IdP | SaaS-OS, then IdP token endpoint | IdP |
| **Identity result SaaS-OS trusts** | Signed ID token | Signed ID token | Signed ID token (same pipeline) | Provider session lookup (proprietary) | Tokens | Provider session/token |
| **MFA** | IdP UI | App | Adapter drives factor checks | Adapter | No (no interactive factors) | Browser |
| **Passkeys** | IdP origin | App origin | Product origin (RP ID = product domain) | Product origin | No | IdP API; RP ID mismatch issues |
| **Password recovery** | IdP UI | App | SaaS-OS endpoints, then provider API | Same as C | No | IdP API |
| **Session model** | SaaS-OS session plus IdP browser SSO cookie | Same as A | SaaS-OS session only in browser; IdP session held server-side | Same as C | SaaS-OS session | Browser holds provider tokens |
| **Logout** | SaaS-OS only; IdP SSO survives | Same as A | SaaS-OS session and IdP session terminated server-side | Same as C | SaaS-OS | Browser |
| **Provider neutrality** | Full (pure OIDC) | None; login UI *is* ZITADEL | Contract neutral; one adapter per provider | Weak; identity result proprietary | Protocol-neutral, but deprecated | None; product code calls IdP |
| **Privileged credential location** | None needed | Login app holds a login-client PAT | SaaS-OS backend holds a login-client credential | Same as C | Client secret | Would need to be in browser; not possible |
| **Complexity** | Implemented | Deploy and theme another app | New boundary, adapter, endpoints, UI | Less than C | Low | n/a |
| **Status** | Works; fails requirement | Fails "product-owned" and "replaceable" | **Candidate** | Rejected (below) | Rejected (below) | Rejected (below) |

Rejections, with reasons:

- **B** keeps the login experience owned by the provider's application. A
  provider swap would replace the login UI, and products could not own the
  page. It fails "product-owned" and "provider replaceable behind the
  boundary".
- **D** drops the OIDC authorization-code exchange and signed ID-token
  validation, and replaces them with trust in a proprietary session lookup.
  That discards `saas_os/core/identity`'s strongest existing control (algorithm
  allowlist, JWKS signature, `iss`/`aud`/`nonce`) and makes the identity
  result provider-proprietary (ADR-0005 "Future Migration Path"). C gives the
  same UX while keeping that control.
- **E** (ROPC) is removed in OAuth 2.1 and discouraged by the OAuth 2.0
  Security BCP. It cannot carry interactive MFA or WebAuthn, and ZITADEL does
  not offer it for human users.
- **F** is not buildable against ZITADEL. `CreateSession`/`SetSession` require
  `session.write` and `CreateCallback` requires `session.link` (protos,
  "Required permissions"). These are privileged login-client permissions that
  cannot be given to a browser. It would also require IdP CORS, expose the IdP
  host, and put the provider session token (which ZITADEL documents as usable
  as an OAuth2 access token to ZITADEL's own APIs) into JavaScript.

---

## 4. Recommended architecture: C, server-side embedded login with OIDC completion

### 4.1 Principle

Replace only the **interactive authentication step** (what the provider's
hosted UI did) with a SaaS-OS-mediated, product-rendered step. Keep
everything before and after it unchanged:

- **Before:** the same `begin_login_transaction()` (state, nonce, PKCE S256).
- **After:** the same `exchange_authorization_code()`, `validate_id_token()`,
  `get_or_create_user_for_external_identity()`, `issue_session()`.

The provider still issues the authorization code and the signed ID token.
SaaS-OS still redeems and validates them exactly as today. The only new thing
is *who drives the provider's login*: SaaS-OS (server-to-server) instead of
the browser (hosted UI).

### 4.2 Answers to the ten required questions

| # | Question | Answer |
|---|---|---|
| 1 | What the browser talks to | Only the product origin: the product's login page and SaaS-OS `/auth/*` JSON endpoints behind the same Caddy site. Never the IdP host. |
| 2 | What SaaS-OS talks to | The IdP, server-to-server, on the private identity network: (a) the OIDC authorize endpoint (to create the provider auth request); (b) the provider login-client API (ZITADEL: Session API v2, OIDC Service v2, and Settings/User v2 for policy, recovery, and enrollment); (c) the token endpoint and JWKS (unchanged). |
| 3 | What the IdP talks to | Nothing on the request path. Optionally its own SMTP/SMS if the provider sends messages; the recommendation is that SaaS-OS sends them (§4.6). |
| 4 | Where credentials are submitted | Browser to SaaS-OS over TLS (same origin, POST, JSON). SaaS-OS forwards them in memory to the provider login-client API. Never persisted, logged, or echoed. |
| 5 | Where tokens are exchanged | SaaS-OS, at the provider token endpoint, using the code SaaS-OS itself obtained from the provider's auth-request completion. Unchanged `exchange_authorization_code()`. |
| 6 | Where the application session is established | SaaS-OS `issue_session()`, unchanged. The session cookie is the only credential the browser ever holds. |
| 7 | Who owns session state | SaaS-OS owns the application session (`core.sessions`). The provider owns its login session. Its handle (id and token) is held **server-side only**, encrypted, bound to the SaaS-OS login transaction and then to the SaaS-OS session. |
| 8 | Who owns credentials | The identity provider: passwords, TOTP secrets, passkey public keys, recovery codes, and lockout state. SaaS-OS stores none of them. |
| 9 | How MFA and passkeys fit | Additional steps of the same login transaction. The adapter requests provider challenges; SaaS-OS returns neutral "next step" descriptors; the browser performs WebAuthn on the product origin. |
| 10 | Logout and revocation | SaaS-OS revokes its session (unchanged) **and** terminates the linked provider session server-side. No browser redirect to an end-session endpoint is needed, because the browser has no provider cookies. |

### 4.3 Sequence: password, then optional second factor

```text
Browser (product page)        SaaS-OS                                     IdP (ZITADEL)
 │ POST /auth/embedded/start ──▶│ begin_login_transaction()               │
 │   (no body)                  │ adapter.start(tx):                      │
 │                              │   GET authorize?client_id&redirect_uri& │
 │                              │     state&nonce&code_challenge ─────────▶│ creates auth request
 │                              │◀── 302 Location: <login base>?authRequest=V2_… (not followed)
 │                              │   store provider auth-request id (encrypted) on tx
 │◀── 200 {step:"identify"} ────│ Set-Cookie tx (HttpOnly, Secure, SameSite=Lax/Strict)
 │                              │
 │ POST /auth/embedded/password │                                          │
 │   {login_name, password} ───▶│ origin + tx checks, rate limits          │
 │                              │ adapter.authenticate_password():         │
 │                              │   POST /v2/sessions {checks:{user,password}} ─▶│
 │                              │◀── session_id, session_token ─────────── │
 │                              │   store both encrypted on tx; discard pw │
 │                              │ adapter.next_step():                     │
 │                              │   policy/factors (e.g. MFA required, user has TOTP)
 │◀── 200 {step:"second_factor",│                                          │
 │        options:["totp"]} ────│                                          │
 │ POST /auth/embedded/totp {code} ─▶│ PATCH /v2/sessions/{id} {checks:{totp}} ─▶│
 │                              │◀── new session_token (old invalidated) ──│
 │                              │ adapter.complete():                      │
 │                              │   POST /v2/oidc/auth_requests/{id}        │
 │                              │     {session:{session_id,session_token}} ─▶│
 │                              │◀── callback_url = redirect_uri?code&state │  (treated as a credential)
 │                              │   parse code+state server-side; never sent to browser
 │                              │ consume_login_transaction(tx, state)     │
 │                              │ exchange_authorization_code(code, verifier) ─▶│ token endpoint
 │                              │ validate_id_token(nonce) + amr policy    │
 │                              │ get_or_create_user(iss, sub); issue_session()
 │                              │ link provider session ref to SaaS-OS session
 │◀── 200 {step:"done", redirect:AUTH_POST_LOGIN_PATH}                     │
 │     Set-Cookie session (HttpOnly, Secure, SameSite=Lax); clear tx cookie │
```

### 4.4 Sequence: passkey (phishing-resistant)

```text
Browser                                  SaaS-OS                          IdP
 │ POST /auth/embedded/passkey/begin {login_name?} ─▶│ adapter.begin_passkey(rp_id = product RP ID)
 │                                                   │  CreateSession/SetSession with
 │                                                   │  challenges.webAuthN{domain, user_verification=REQUIRED} ─▶│
 │◀── 200 {step:"webauthn", publicKey: <request options>} ◀─────────────────────────────│
 │ navigator.credentials.get(publicKey)  (origin = product; RP ID = product domain)
 │ POST /auth/embedded/passkey/finish {assertion} ─▶│ SetSession checks.webAuthN ─▶│ verifies signature, origin, RP ID
 │                                                   │ complete() → code → same OIDC tail as §4.3
```

Verified constraint (challenge.proto): the WebAuthn `domain` "must be either
the exact domain or a top-level domain of the origin of the request". The RP ID
is therefore the **product's** registrable domain (for example `example.com`),
which covers `app.example.com`. Passkeys stay origin-bound to the product, so
a look-alike domain cannot use them. That is the phishing-resistance property.

### 4.5 Whether credentials should traverse SaaS-OS

| Concern | Browser → SaaS-OS → IdP (recommended) | Browser → IdP API |
|---|---|---|
| TLS | One public TLS hop (Caddy). Internal hop on the private `identity-edge` network with ZITADEL's own TLS (already in `docker-compose.prod.yml`). | Public TLS to IdP host. |
| Credential exposure | Plaintext in SaaS-OS process memory for one request; must never be logged (ADR-0020 redaction applies to all keys, and the password field must be excluded explicitly). | Never in SaaS-OS. |
| Privileged API credential | Stays on the server. | Would have to be in the browser. Disqualifying for ZITADEL (§3 F). |
| CSRF | Same-origin POST. Add an explicit Origin/`Sec-Fetch-Site` check (§7). | Cross-origin; relies on IdP. |
| CORS | None needed (same origin; no CORS middleware exists). | IdP must allow the product origin. |
| Session fixation | SaaS-OS mints a new session secret at completion. | Browser holds provider session. |
| Token handling | Code, ID token, and provider session token stay server-side. | Provider token in JavaScript. |
| Browser storage | Nothing but HttpOnly cookies. | Tokens in memory or storage (XSS-reachable). |
| Cookies | `HttpOnly; Secure; SameSite=Lax` (existing). Tx cookie scoped to `/auth`. | Provider cookies or tokens. |
| Lifetime | SaaS-OS session lifetime (12 h, existing). Provider session lifetime set to match or less. | Provider-driven. |
| Logout | Server-side, both sessions. | Browser must call IdP. |
| MFA | Server-side orchestration of provider checks. | Browser orchestration. |

The trade SaaS-OS accepts is **credential transit, not credential storage**.
This is the same exposure any reverse proxy terminating TLS already has, and
the same posture as ZITADEL's own Login V2 app, which is a server-side login
client. It is the only arrangement that keeps the privileged login-client
credential and the provider session token off the browser.

### 4.6 Recovery, enrollment, and logout

- **Password reset:** `POST /auth/embedded/recovery/request {login_name}`
  always returns 202 (non-enumerating). The adapter resolves the user and calls
  the provider's reset. For ZITADEL, `POST /v2/users/{user_id}/password_reset`
  supports both `send_link` (with URL template) and `return_code`. The
  recommendation is `return_code`, with SaaS-OS delivering the message via the
  existing `saas_os/core/email`, so branding and templates are product-owned and
  provider-neutral. The code is a short-lived credential: never logged, never
  stored. Completion: `POST /auth/embedded/recovery/complete {code,
  new_password}` goes to `POST /v2/users/{user_id}/password` with the
  verification code. The user id is carried in an encrypted, server-side
  recovery record, not the URL.
- **MFA and passkey enrollment:** authenticated SaaS-OS account endpoints
  (require a valid SaaS-OS session and recent authentication) that proxy to
  provider enrollment. For ZITADEL that is `RegisterPasskey`,
  `VerifyPasskeyRegistration`, `RegisterTOTP`/`VerifyTOTPRegistration`. This
  is needed so users never land in the ZITADEL console.
- **Logout:** existing `revoke_session()`, plus `adapter.terminate(provider
  session ref)` (ZITADEL: `DELETE /v2/sessions/{id}`). The provider call is
  best-effort after the local revoke: local revocation alone already ends
  SaaS-OS access, and a failed provider call is logged and retried by the
  existing `session_retention` sweep.
- **Revocation:** unchanged. SaaS-OS session revocation is immediate.
  Provider-side user deactivation still does not end an existing SaaS-OS
  session before its expiry (a pre-existing limitation, unchanged by this
  design; see §7).

---

## 5. Provider-neutral contract (conceptual; not implemented)

Naming follows existing conventions (`IdentityProvider`, `BillingProvider`,
`EmailProvider`; a Protocol in `core/<module>/provider.py`, provider-named
adapters in their own module like `saas_os/core/billing/stripe_provider.py`). No
ZITADEL term appears in the contract.

### 5.1 Interfaces

```text
saas_os/core/identity/provider.py  (generic, existing module)

  IdentityProvider              (existing, unchanged; OIDC relying party:
                                 build_authorization_url, exchange_authorization_code,
                                 validate_id_token, ...)

  EmbeddedLoginProvider         (NEW Protocol; interactive authentication capability)
    start(authorization: AuthorizationParams) -> ProviderLoginHandle
    authenticate_password(handle, login_name, password) -> LoginStep
    begin_passkey(handle, login_name | None, rp_id) -> LoginStep      # returns WebAuthn options
    finish_passkey(handle, assertion: WebAuthnAssertion) -> LoginStep
    verify_second_factor(handle, factor: SecondFactorKind, code) -> LoginStep
    complete(handle) -> AuthorizationResponse        # code + state, from the provider
    terminate(session_ref: ProviderSessionRef) -> None
    request_password_reset(login_name) -> RecoveryHandle | None       # None = unknown; never surfaced
    complete_password_reset(recovery: RecoveryHandle, code, new_password) -> None

  AccountSecurityProvider       (NEW Protocol, later phase; authenticated enrollment)
    list_factors / begin_passkey_enrollment / finish_passkey_enrollment /
    begin_totp_enrollment / finish_totp_enrollment / remove_factor
```

Neutral value types: `AuthorizationParams` (client id, redirect URI, state,
nonce, code challenge; built from the existing `StartedLogin`),
`ProviderLoginHandle` / `ProviderSessionRef` / `RecoveryHandle` (opaque
serialized strings, only ever stored encrypted),
`LoginStep = Identify | Password | SecondFactor(options) | WebAuthn(request_options) | Complete | Failed(kind)`,
`SecondFactorKind = TOTP | OTP_EMAIL | OTP_SMS | RECOVERY_CODE`,
`AuthorizationResponse(code, state)`.

`EmbeddedLoginProvider` produces an **authorization code**, never an identity.
The identity still comes only from `IdentityProvider.validate_id_token()`.
That is the property that keeps a buggy or compromised adapter from minting a
SaaS-OS user directly.

### 5.2 Boundaries

| Boundary | Owner | Rule |
|---|---|---|
| **HTTP surface** | `saas_os/api/auth` (new `embedded_routes.py`) | Orchestration only, like `routes.py`: origin/tx/rate-limit checks, calls into `saas_os.core.identity`, fixed generic errors. Mounted only when `AUTH_LOGIN_MODE=embedded`. |
| **Login orchestration** | `saas_os/core/identity` (new `embedded_login.py`) | Owns the step state machine and transaction binding, and calls the Protocol. Provider-agnostic. |
| **Provider adapter** | `saas_os/core/identity/zitadel_login.py` (the only module naming ZITADEL) | Implements the Protocol with httpx calls to the provider API. An import-linter contract (like the Stripe precedent) forbids importing it anywhere but the factory. |
| **Session boundary** | `saas_os/core/identity/sessions.py` (existing) | Unchanged issuance and validation. New: an optional encrypted provider-session reference on the SaaS-OS session, used only by logout. |
| **Transaction boundary** | `saas_os/core/identity/login_transactions.py` (existing) | Extended with encrypted provider handle fields (`saas_os.core.crypto.EncryptionService`, ADR-0019) and a step/attempt counter. Still single-use and still consumed with `SELECT … FOR UPDATE`. |
| **Error boundary** | `saas_os/core/identity/errors.py` | Adapter maps every provider error to a small neutral set: `CredentialsRejected`, `FactorRequired`, `LoginExpired`, `AccountLocked`, `ProviderUnavailable`, `LoginFlowInvalid`. HTTP returns fixed messages (401/400/429/503); never provider bodies, never *which* check failed. |
| **Audit boundary** | `saas_os/api/auth` structured events | New neutral events (`auth_login_step`, `auth_login_factor_failed`, `auth_recovery_requested`, …) with request id, outcome class, factor *kind*; never login name, password, code, or token. Pre-tenant limitation unchanged. |

### 5.3 Configuration

- `AUTH_LOGIN_MODE = hosted | embedded` (default `hosted`, which is today's
  behavior). In `embedded` mode, `GET /auth/login` is not the entry point.
- Provider-neutral application settings: `AUTH_WEBAUTHN_RP_ID` (product
  registrable domain) and `AUTH_PUBLIC_ORIGIN` (for origin checks).
- Adapter credential: a login-client credential read through
  `saas_os.infra.secrets`. The name should be neutral (for example
  `IDENTITY_LOGIN_CLIENT_TOKEN`), because the backend reads it as SaaS-OS
  application configuration (ADR-0023 contract).

---

## 6. ZITADEL adapter (provider-specific implementation)

Everything in this section lives only in the adapter, the bootstrap tooling,
and deployment configuration. None of it is visible to products or the generic
contract.

| Contract operation | ZITADEL v4.19.0 mechanism (verified unless marked) |
|---|---|
| Route authorize to a login client | Per-application `login_version.login_v2.base_uri` (`application/v2/login.proto`; accepted by `CreateOIDCApplicationRequest.login_version`). The instance keeps `LOGINV2_REQUIRED=false`, so hosted-mode apps stay on v1. |
| `start` | Server-side `GET /oauth/v2/authorize` (standard params incl. PKCE). ZITADEL creates a V2 auth request (`IDPrefixV2`) and 302s to the login base URI with the auth request id. The adapter reads `Location` and does not follow. **VERIFY:** exact query-parameter name and that a server-initiated authorize (no browser cookies) is accepted; fallback in §9. |
| Inspect request | `GET /v2/oidc/auth_requests/{id}` (`session.read`) |
| `authenticate_password` | `POST /v2/sessions` `checks.user` + `checks.password`, which returns `session_id` and `session_token` |
| `verify_second_factor` | `PATCH /v2/sessions/{id}` `checks.totp` / `otp_email` / `otp_sms` / `recovery_code`. Each call rotates the token (proto: "previous token will be invalidated"). |
| `begin_passkey` / `finish_passkey` | `challenges.web_auth_n{domain = AUTH_WEBAUTHN_RP_ID, user_verification_requirement = REQUIRED}`, then `checks.web_auth_n` |
| Policy / available factors | Settings v2 login settings and `ListAuthenticationMethodTypes` (`user_service.proto`). The adapter must decide whether MFA is required. **VERIFY:** whether `CreateCallback` itself enforces MFA policy; assume it does not. |
| `complete` | `POST /v2/oidc/auth_requests/{id}` `{session:{session_id, session_token}}` (`session.link`), which returns `callback_url` (proto: "must be treated as credentials"). The adapter parses `code` and `state`. |
| `terminate` | `DELETE /v2/sessions/{id}` |
| Password reset | `POST /v2/users/{user_id}/password_reset` (`return_code`), then `POST /v2/users/{user_id}/password` with verification code |
| Credential | A dedicated login-client machine user holding the `session.read/write/link` permissions (**VERIFY:** role name, expected `IAM_LOGIN_CLIENT`). **Never** the bootstrap IAM_OWNER PAT. It is provisioned by the bootstrap tooling (a later phase) and delivered to `backend` via `saas_os.infra.secrets`. |
| Lockout and brute force | ZITADEL lockout policy (max password/OTP attempts) stays authoritative, plus SaaS-OS rate limits (§7). |
| Org scoping | Login name resolution must be scoped to the application's organization. **VERIFY:** `CheckUser` login-name semantics with multiple orgs. |

Bootstrap impact (later phase, not now): `saas-os-local-identity` gains an
opt-in to set `login_version.login_v2.base_uri` and to create the login-client
machine user. Default behavior stays exactly as today.

---

## 7. Security threat analysis

| Threat | Analysis and control |
|---|---|
| **Credential handling** | Transit only. Password, OTP, and reset code exist in one request's memory. They are excluded from logs (ADR-0020 plus an explicit field denylist test), never persisted, never returned. Request bodies are size-bounded. |
| **Phishing resistance** | Passkeys are bound to the product RP ID and origin: strong. Passwords and OTP are phishable (as with any form); the mitigation is passkey-first UX and an MFA policy. Embedded login removes the "trust a redirect to another host" habit, which is a phishing benefit. |
| **Session fixation** | A new 256-bit SaaS-OS secret is minted at completion. The tx cookie is cleared. Any pre-existing session cookie is overwritten. The provider session token rotates on every check. |
| **CSRF / login CSRF** | Every embedded endpoint is POST JSON, requires the HttpOnly tx cookie bound to a live single-use transaction, and passes a strict Origin (or `Sec-Fetch-Site: same-origin`) check against `AUTH_PUBLIC_ORIGIN`. This is a small explicit check, not a framework. Login CSRF (attacker logs a victim into the attacker's account) is blocked because the tx cookie originates only from the victim's own `start`. |
| **XSS** | The password field lives in the product page DOM. Product responsibilities: a strict CSP on the login route and no third-party scripts there. SaaS-OS never exposes tokens to JavaScript (HttpOnly only). |
| **Token leakage** | `callback_url`/code, ID token, provider session token, and login-client credential never leave the backend. Provider handles are stored encrypted (`saas_os.core.crypto`) and deleted on consume. |
| **Cookie security** | Existing `HttpOnly; Secure (forced in prod); SameSite=Lax`. The tx cookie is `Path=/auth`, 10 min. Consider `SameSite=Strict` for the tx cookie (no cross-site navigation needed in embedded mode). |
| **Brute force** | Three layers: (1) existing per-address `auth:` limiter; (2) a new per-account key (hash of normalized login name) through the *same* `saas_os.infra.ratelimit`; (3) provider lockout policy. A per-transaction attempt cap forces a restart. Fail-closed on limiter outage (existing). |
| **MFA** | Policy is decided by the provider settings the adapter reads. **Defense in depth:** SaaS-OS checks the standard `amr` claim (RFC 8176) in the validated ID token against `AUTH_REQUIRE_MFA`. A misbehaving adapter, or a stolen login-client credential used with a user-only session, still cannot yield a SaaS-OS session without a credential factor. **VERIFY:** ZITADEL's `amr` values. |
| **Login-client credential compromise** | High value: it can create sessions and finalize auth requests. Mitigations: dedicated least-privilege machine user; only `backend` holds it; tier-1 secret handling (ADR-0012); rotation runbook; the `amr` check above; the provider on a private network. |
| **Passkeys** | The RP ID must equal the product registrable domain. Passkeys enrolled earlier via the hosted UI on `id.example.com` (RP ID `id.example.com`) are **not** usable on `app.example.com`. Migration must re-enroll or pre-register with RP ID = registrable domain. |
| **Password reset** | Non-enumerating 202. Single-use provider code with short TTL. SaaS-OS delivers email. All SaaS-OS sessions for the user are revoked on reset completion (new behavior; uses the existing `revoke_session`). |
| **Logout / revocation** | Local revoke first (authoritative), then provider session termination. No provider SSO cookie exists in the browser, which closes today's "IdP session survives logout" gap. |
| **Account enumeration** | Single combined `{login_name, password}` step with one generic failure. Constant response shape. Timing equalized where the adapter can (provider "ignore unknown usernames" setting, **VERIFY**). Passkey-with-username flows inherently reveal existence; offer discoverable (usernameless) passkeys. Recovery is always 202. |
| **Tenant isolation** | Unchanged. Login is pre-tenant and establishes identity only. Tenant access still requires membership plus `saas_os/core/rbac`. The embedded flow never accepts a tenant or user id from the client. |
| **Audit logging** | Structured, correlated, secret-free events per step and outcome (§5.2). Pre-tenant audit-table limitation unchanged (documented). |
| **Provider availability** | Any adapter transport error returns 503 "Identity provider unavailable" (existing semantics); nothing falls back to a weaker path. |

---

## 8. Migration strategy

1. **Hosted stays the default.** `AUTH_LOGIN_MODE` defaults to `hosted`.
   `GET /auth/login` and `/auth/callback` are unchanged, as are
   `IdentityProvider`, `saas-os-local-identity` defaults, the live-ZITADEL
   gate, and the substitution tests.
2. **Additive surface.** Embedded endpoints mount only in `embedded` mode. The
   OIDC tail (exchange, validate, user mapping, session) is shared, not
   forked.
3. **Per-deployment switch.** ZITADEL login version is per application, so a
   deployment switches by (a) setting the app's `login_v2.base_uri` via
   bootstrap opt-in and (b) `AUTH_LOGIN_MODE=embedded`. Rollback reverses both.
   Side-by-side validation uses a separate environment or a second application
   (a second client id), never a mixed-mode single app.
4. **Passkey RP ID** must be settled before any production passkey
   enrollment (see §7).
5. **Existing users** keep their provider credentials. Nothing is migrated,
   because credentials never move.
6. **Deprecation of hosted mode** is a separate, later decision. This design
   does not remove it.

---

## 9. Implementation phases (future; each independently auditable)

| # | Phase | Scope | Exit criteria |
|---|---|---|---|
| 0 | **Architecture / ADR** | New ADR (§10); amend `SECURITY.md` §2 wording. | Human acceptance. |
| 1 | **ZITADEL verification spike** (throwaway, no product code) | Against local v4.19.0, confirm every **VERIFY** item: server-side authorize and `Location` shape; login-client role; `CreateCallback` MFA enforcement; `amr` values; `ignoreUnknownUsernames`; org-scoped login names. | Written findings. If server-side authorize fails, choose the fallback: one invisible browser 302 hop through the IdP host with no rendered UI, and record it. |
| 2 | **Provider-neutral boundary** | `EmbeddedLoginProvider` Protocol, neutral types and errors, `FakeEmbeddedLoginProvider`, contract/substitution tests. No HTTP, no provider. | Tests prove orchestration without any provider. |
| 3 | **Transaction and session storage** | Migration: encrypted provider-handle fields on login transactions; optional encrypted provider-session ref on sessions; attempt counter. | Migration and rollback tests; encryption round-trip; single-use preserved. |
| 4 | **ZITADEL adapter** | `zitadel_login.py` (httpx), import-linter isolation contract, secret wiring; bootstrap opt-in for `login_v2.base_uri` and the login-client user. | Adapter unit tests (MockTransport); live gated test (`ZITADEL_LIVE_TEST`). |
| 5 | **Embedded login flow (password)** | `saas_os/api/auth/embedded_routes.py`: start, password, complete; origin checks; per-account rate limit; `AUTH_LOGIN_MODE`. Minimal reference login page in `frontend/`. | End-to-end password login locally, with the browser never contacting the IdP host. |
| 6 | **Session integration** | Link provider session to SaaS-OS session; `amr` policy check; logout terminates both. | Revocation and fixation tests. |
| 7 | **MFA and passkeys** | TOTP/OTP/recovery-code steps; WebAuthn login; authenticated enrollment (`AccountSecurityProvider`). | Passkey login on product origin; MFA-required policy enforced end-to-end. |
| 8 | **Recovery** | Reset request/complete via `saas_os/core/email`; revoke sessions on reset. | Non-enumeration and single-use tests. |
| 9 | **Security testing** | Threat-model verification (§7): CSRF/origin, enumeration timing, brute-force layers, log-redaction scan, cookie flags, XSS/CSP guidance. | Security review sign-off. |
| 10 | **End-to-end validation** | Browser automation (Playwright) across both modes, both compose topologies; rollback drill. | Hosted mode unchanged; embedded mode passes; documented runbook. |

---

## 10. ADR recommendation

**A new ADR is required**, because this reverses an Accepted decision's
explicit clause: ADR-0005's "does not … implement its own login form logic",
restated in `docs/SECURITY.md` §2. It also resolves ADR-0023 §15's recorded
limitation. Amending ADR-0023 alone would be wrong: ADR-0023 is a Draft about
deployment topology, while this is an authentication-mechanism decision.

Proposed (not created):

- **Title:** ADR-0026: Product-owned embedded login through a provider-neutral
  login boundary.
- **Decision summary:**
  - SaaS-OS offers an opt-in embedded login mode (default remains hosted OIDC).
  - The product renders the login UI on its own origin. The browser talks only
    to SaaS-OS.
  - SaaS-OS drives the provider's supported login-client API server-to-server
    through a provider-neutral `EmbeddedLoginProvider` boundary.
  - The flow always completes through the standard OIDC authorization-code
    exchange and ID-token validation. The adapter yields an authorization code,
    never an identity.
  - Credentials transit SaaS-OS in memory but are never stored. The provider
    remains the sole credential authority.
  - Provider handles are server-side and encrypted. The login-client
    credential is a least-privilege secret held only by the backend.
  - The ADR amends ADR-0005's login-form clause and `SECURITY.md` §2, and
    supersedes ADR-0023 §15's known-limitation note. ADR-0023 §9's subdomain
    topology is unchanged; in embedded mode, only the backend reaches it.

---

## 11. Explicit non-goals of this design

- No SaaS-OS password, TOTP secret, or passkey store.
- No custom authentication protocol and no ROPC.
- No ZITADEL SDK (plain HTTPS calls to documented v2 APIs, like the existing
  bootstrap).
- No change to tenant resolution, RBAC, membership, or API keys.
- No refresh-token persistence.
- Self-service sign-up and account linking are not covered (separate future
  decisions; ADR-0023 Phase 5).

---

## 12. Phase 1 verification results (ZITADEL v4.19.0)

**Pinned version.** `ghcr.io/zitadel/zitadel:v4.19.0`, the only ZITADEL
reference in this repository:
- `docker-compose.yml:166` and `docker-compose.prod.yml:378`;
- also referenced by `tests/infra/db/test_zitadel_backup_restore_drill_integration.py`.

No ZITADEL SDK, protobuf package, or generated client is a dependency.
`saas-os-local-identity` calls the HTTP API directly.

**Method.** Every result below carries one of two evidence labels:

- **Source**: read from ZITADEL's v4.19.0 source and protos at the `v4.19.0`
  tag (`raw.githubusercontent.com/zitadel/zitadel/v4.19.0/...`). zitadel.com
  remained unreachable (egress proxy).
- **Live**: exercised against a disposable local ZITADEL. The Docker daemon is
  unavailable in this environment, so the instance ran as the official release
  binary `zitadel-linux-amd64.tar.gz` v4.19.0 (SHA-256 matched the release's
  `checksums.txt`; the binary reports `zitadel version v4.19.0`). It used a
  throwaway local PostgreSQL 16 and the same first-instance settings as
  `docker-compose.yml`, except `ExternalDomain=localhost` instead of
  `zitadel.localhost`, which does not affect the APIs tested.

Details of the live run:
- **Test identities.** Random, disposable passwords, never printed or stored.
- **Provisioning.** The bootstrap `IAM_OWNER` PAT was used only to provision
  spike fixtures, never for login operations.
- **SaaS-OS code.** SaaS-OS's own, unmodified `exchange_authorization_code()`
  and `validate_id_token()` were imported read-only to consume the results.
- **Teardown.** The instance, database, and all secret material were
  destroyed afterwards.
- **Not exercised.** No real browser was used. WebAuthn used a software
  authenticator (ES256, `none` attestation).

Status key: **VERIFIED** (live, unless marked *source only*), **NOT
VERIFIED**, **CONTRADICTED** (evidence contradicts an assumption in this
document).

### 12.1 Resolution of the six Phase 1 gates (ADR-0026 §5)

**Gate 1: server-initiated authorize and redirect shape.**
- *Behavior:* `GET /oauth/v2/authorize` (standard parameters, PKCE S256) sent
  server-to-server with no browser cookies, for an app with
  `login_version.login_v2.base_uri`.
- *Status:* **VERIFIED.**
- *Evidence:* Live: `302 Location: <base_uri>/login?authRequest=V2_<id>`.
  The single parameter is `authRequest`, and `/login` is appended to the base
  URI. ZITADEL also sets a user-agent cookie on the *calling server's*
  response, which the server discards. For the same instance, an app without
  `login_v2` still redirects to the hosted `/ui/login/login?authRequestID=…`.
- *Implication:* No browser request to ZITADEL is needed to start a login. The
  fallback (a browser 302 hop through the provider host) is **not** needed.

**Gate 2: login-client role.**
- *Behavior:* The role granting the login-client permissions.
- *Status:* **VERIFIED that `IAM_LOGIN_CLIENT` exists; CONTRADICTED that it
  is suitable.**
- *Evidence:* Source: `cmd/defaults.yaml` `IAM_LOGIN_CLIENT` holds
  `session.read/write/link/delete` **plus** `iam.member.write`,
  `org.member.write`, `project.member.write`, `user.write`,
  `user.grant.write`, `user.credential.write` and more. Live: a PAT with
  `IAM_LOGIN_CLIENT` created a machine user and **granted it `IAM_OWNER`**
  (both 200).
- *Implication:* The built-in role must **not** be used. A stolen credential
  would mean full instance takeover. See §12.3 R1 for the working
  least-privilege alternative.

**Gate 3: does `CreateCallback` enforce MFA or credential policy?**
- *Behavior:* What `CreateCallback` requires of the linked session.
- *Status:* **VERIFIED: it enforces neither.**
- *Evidence:* Source: `LinkSessionToAuthRequest` checks auth-request state
  (single use), login client or `session.link`, `CheckIsActive` (exists and not
  terminated or expired), session token, project permission, and org. **No
  factor or policy check.** Live:
  - a session with **only a user check (no credential)** was accepted and
    yielded a correctly signed ID token for that user, with **no `amr`
    claim**;
  - with the instance login policy `forceMfa=true`, a password-only session
    was accepted and produced `amr=["pwd"]`.
- *Implication:* Anyone holding a login-client credential can mint a valid
  code for any user without that user's credentials. SaaS-OS-side `amr`
  enforcement is **mandatory, not defense in depth** (§12.3 R2).

**Gate 4: `amr` values.**
- *Behavior:* `amr` values in ID tokens.
- *Status:* **VERIFIED** (live for pwd, pwd+totp and no-factor; *source only*
  for passkey, U2F and recovery code).
- *Evidence:* Live:
  - password gives `["pwd"]`;
  - password + TOTP gives `["pwd","otp","mfa"]`;
  - no credential factor omits `amr` entirely.

  Source `internal/api/oidc/amr.go`:
  - user-verified passkey gives `user`+`mfa`;
  - U2F gives `user`;
  - OTP, TOTP and recovery code give `otp`;
  - `mfa` is added when there are two or more factors.
- *Implication:* SaaS-OS can decide authentication strength from validated
  claims alone.

**Gate 5: "ignore unknown usernames".**
- *Behavior:* Whether the provider setting suppresses unknown-user disclosure.
- *Status:* **CONTRADICTED.**
- *Evidence:* Live: with `ignoreUnknownUsernames=true`, `CreateSession` still
  answers **404 "User could not be found"** for an unknown login name, versus
  400 "Password is invalid" for a known user.
- *Implication:* The setting affects only the hosted UI. SaaS-OS must collapse
  every outcome itself (§12.3 R4).

**Gate 6: login-name resolution and org scoping.**
- *Behavior:* Login-name resolution across organizations.
- *Status:* **VERIFIED** for default settings; **NOT VERIFIED** with
  `userLoginMustBeDomain`.
- *Evidence:* Live: usernames are instance-unique by default (creating `bob` in
  a second org failed "User already exists"), and `loginName=bob` resolved to
  the one user. Source: `LinkSessionToAuthRequest` rejects a session whose
  user's org differs from an org-scoped auth request (`COMMAND-59ljd`).
- *Implication:* No ambiguity under defaults. Org-suffixed login names are an
  untested configuration.

### 12.2 Other requested verifications

**1. Session API v2.**
- *Status:* **VERIFIED.**
- *Evidence:* Live:
  - `POST /v2/sessions` returns `201 {sessionId, sessionToken, details}`;
  - `PATCH /v2/sessions/{id}` adds checks and **rotates the token** (the old
    token is then rejected, 403 `COMMAND-sGr42`);
  - `GET /v2/sessions/{id}` lists `factors`;
  - `DELETE /v2/sessions/{id}` terminates.
- *Implication:* Supports the design.

**2. Password authentication.**
- *Status:* **VERIFIED.**
- *Evidence:* Live:
  - wrong password gives 400 `COMMAND-3M0fs`;
  - unknown user gives **404** `QUERY-Dfbg2`;
  - locked user gives 400 `Errors.User.NotActive (SESSION-Gj4ko)`, even for a
    user-only check.

  **Lockout is off by default.** With the default policy, 4 wrong attempts
  followed by the correct password succeeded; with `maxPasswordAttempts=3` the
  account locked.
- *Implication:* Responses disclose account existence and lock state, and
  provider lockout requires explicit configuration (§12.3 R4 and R5).

**3. MFA (TOTP/OTP).**
- *Status:* **VERIFIED** (TOTP live; OTP SMS/email *source only*).
- *Evidence:* Live: after a password check, `CreateSession` returns no
  "next factor required" signal. The login client can read
  `GET /v2/settings/login` (`forceMfa`) and
  `GET /v2/users/{id}/authentication_methods` to decide the next step. TOTP was
  checked via `PATCH` `checks.totp`.
- *Implication:* The adapter must compute next steps. SaaS-OS enforces the
  result through `amr`.

**4. Recovery codes.**
- *Status:* **VERIFIED.**
- *Evidence:* Live: `POST /v2/users/{id}/recovery_codes` generates codes, and
  `checks.recoveryCode` records a `recoveryCode` factor. Reuse is rejected (400
  `DOMAIN-6uvh0`).
- *Implication:* Supported, and counts as `otp` in `amr`.

**5. Passkeys/WebAuthn.**
- *Status:* **VERIFIED** (software authenticator, no real browser).
- *Evidence:* Live:
  - registration via `POST /v2/users/{id}/passkeys {domain}` and
    `POST …/passkeys/{id}` works;
  - login works via `challenges.webAuthN{domain, UV=REQUIRED}`, returning
    `rpId=domain`, then `checks.webAuthN`, giving a `webAuthN` factor with
    `userVerified=true`;
  - an `rpIdHash` mismatch is rejected.

  **An assertion whose `clientDataJSON.origin` was a foreign origin was
  accepted.** Source: `FinishLogin` sets `RPOrigins = [the assertion's own
  origin]`, so ZITADEL does not check it. The proto's "domain must match the
  request origin" rule is also **not** enforced server-side: registering with
  an unrelated domain succeeded.
- *Implication:* The browser's RP ID enforcement still gives phishing
  resistance. However, **SaaS-OS must supply the RP ID itself and validate
  `clientDataJSON.origin` against its public origin** before forwarding
  (§12.3 R6).

**6. Hosted-UI passkey compatibility.**
- *Status:* **VERIFIED (source only): incompatible.**
- *Evidence:* Source `internal/webauthn/converter.go`: a credential is offered
  only if its stored RP ID equals the requested one. Credentials added through
  the console or old login store no RP ID and match only the **instance
  domain** (for example `id.example.com`), which a page on `app.example.com`
  cannot use as an RP ID. Live: a challenge for an RP ID with no matching
  credentials fails (`WEBAU-4G8sw`).
- *Implication:* Hosted-UI passkeys must be re-enrolled for embedded mode.

**7. `CreateCallback` (the 10 questions).**
- *Status:* **VERIFIED.**
- *Evidence:*
  1. **Inputs:** auth request id plus `{sessionId, sessionToken}`.
  2. **Session state required:** an active session and a valid current token;
     no factor requirement.
  3. **Code:** issued by ZITADEL's OP.
  4. **Returns:** `callbackUrl` = `<redirect_uri>?code=…&state=…`.
  5. **Content:** an authorization code, which is a credential.
  6. **One-time use:** live, a second `CreateCallback` gives 400
     `COMMAND-Sx208nt`, and a second code redemption is rejected. The exact
     code lifetime is **NOT VERIFIED**.
  7. **Server-side handling:** live, parsed server-side, with nothing sent to
     a browser.
  8. **Binding to the auth request:** the callback is bound to it. `state`
     matched live, and the `client_id` and `redirect_uri` are those of the
     authorize request.
  9. **Validation:** state and nonce are carried through; SaaS-OS validates
     both.
  10. **Browser involvement:** none required.
- *Implication:* Feeds the unchanged `exchange_authorization_code()`, which was
  verified live.

**8. `login_v2.base_uri`.**
- *Status:* **VERIFIED.**
- *Evidence:* Field `oidcConfiguration.loginVersion.loginV2.baseUri` on
  `CreateApplication`, and in the update API (source). It is per application:
  the hosted app on the same instance is unaffected (live). **ZITADEL does not
  validate the URI:** relative and `ftp://` values were accepted (live).
- *Implication:* Required for the embedded flow. Bootstrap tooling can set it
  later (same API it already calls). SaaS-OS must never follow the returned
  `Location`.

**9. Runtime login-client permissions.**
- *Status:* **VERIFIED.**
- *Evidence:* Live, with a custom role holding exactly `session.read`,
  `session.write`, `session.link`, `session.delete`, `user.read`,
  `user.credential.write`, `policy.read` and `iam.policy.read`:
  - the full authorize → session → callback → SaaS-OS pipeline, settings
    read, factor listing, and session delete all succeeded;
  - creating users and granting `IAM_OWNER` were **denied (403)**.

  **Requesting** a password reset requires `user.write` (source
  `checkPermissionUpdateUser`; live 403 without it, 200 with a role holding
  only `user.read`+`user.write`). **Completing** a reset with the one-time code
  succeeded with the login role alone. `user.write` can deactivate users but
  could not grant IAM roles (live).
- *Implication:* A least-privilege split is achievable (§12.3 R1).

**10. Provider session-token semantics.**
- *Status:* **VERIFIED.**
- *Evidence:* Live:
  - a session token is a **bearer credential for ZITADEL's own APIs as that
    user**: `GET /auth/v1/users/me` and `GET /v2/users/{id}` returned 200 with
    a password+TOTP session token;
  - self-service writes are subject to ZITADEL's own MFA policy ("mfa
    required" under `forceMfa`);
  - a user-only session token is refused (403);
  - tokens rotate on every `SetSession`.

  **Default lifetime: none** (`expirationDate` absent). With `lifetime=5s`,
  the token was refused after expiry (403). After `DELETE`, the session
  returned 404 and the token was unusable.
- *Implication:* Must never reach the browser. It must be stored encrypted
  (`saas_os.core.crypto`) and created with an explicit lifetime (§12.3 R3).

**11. Logout.**
- *Status:* **VERIFIED.**
- *Evidence:* Live: `DELETE /v2/sessions/{id}` with the login-client
  credential. Afterwards `GET` gives 404, `CreateCallback` gives 400
  `COMMAND-Hewfq`, and the token no longer works as a bearer. No browser
  redirect is involved.
- *Implication:* Supports server-side logout. SaaS-OS revokes its own session
  independently (existing).

**12. Password recovery.**
- *Status:* **VERIFIED** for `returnCode`; **NOT VERIFIED** for `sendLink`.
- *Evidence:* Live: `POST /v2/users/{id}/password_reset {returnCode:{}}`
  returns the code. `POST /v2/users/{id}/password {verificationCode}` sets the
  new password; code reuse gives 400 `COMMAND-2M9fs`. An unknown user id gives
  404. Resolving a login name through `POST /v2/users` search works for the
  login client.
- *Implication:* Product-branded recovery through SaaS-OS email works without
  any browser visit to ZITADEL. SaaS-OS must return a uniform 202 regardless
  of these outcomes.

**13. Browser-origin requirement.**
- *Status:* **VERIFIED** (server-to-server exercised; no real-browser run).
- *Evidence:* Every provider interaction was made by the server acting as
  SaaS-OS: authorize, sessions, challenges, callback, token, JWKS, delete, and
  reset. The only browser-side step is WebAuthn `navigator.credentials.*` on
  the product origin, which never contacts ZITADEL.
- *Implication:* The browser only ever needs `product/login`,
  `product/auth/embedded/*` and `product/app/*`. Real-browser confirmation is
  Phase 10.

**14. OIDC security continuity.**
- *Status:* **VERIFIED.**
- *Evidence:* Live, through SaaS-OS's unmodified code:
  - PKCE S256 verifier accepted;
  - `state` round-trips;
  - `nonce` validated;
  - `iss` and `aud` validated;
  - RS256 signature validated via JWKS;
  - `sub` matches the user;
  - code replay rejected.
- *Implication:* The existing pipeline stays authoritative, unchanged.

### 12.3 Required refinements (binding on implementation; within ADR-0026's shape)

None of these changes ADR-0026's architecture. They turn stated requirements
into specifics, and in three places (R1, R2, R4) they correct an expectation
recorded in this document.

- **R1 — Login-client role.** Do not use `IAM_LOGIN_CLIENT`. Define a custom
  instance role through ZITADEL runtime configuration
  (`InternalAuthZ.RolePermissionMappings`; self-hosted operators control this)
  with only: `session.read/write/link/delete`, `user.read`,
  `user.credential.write`, `policy.read`, `iam.policy.read`.
  - Password-reset *requests* need `user.write`: isolate them in a separate
    recovery credential and role (`user.read`, `user.write`) or accept that
    breadth explicitly.
  - Cost: the override must carry ZITADEL's full default mapping list and be
    reconciled on every ZITADEL upgrade.
- **R2 — Mandatory `amr` policy.** SaaS-OS rejects any embedded-mode ID token
  whose `amr` is absent or empty, or lacks a credential factor (`pwd` or
  `user`). When MFA is required, it additionally requires `mfa`. This is the
  only control that stops a login-client credential from being an
  impersonation credential into SaaS-OS.
- **R3 — Provider session lifetime.** Always create provider sessions with an
  explicit `lifetime` no longer than the SaaS-OS session lifetime. The default
  is unlimited.
- **R4 — Enumeration.** The provider distinguishes unknown user (404), wrong
  password (400), and locked (`NotActive`), and `ignoreUnknownUsernames` does
  not apply to the Session API. SaaS-OS must map all of these to one response
  shape. Timing equalization is still to be measured (NOT VERIFIED).
- **R5 — Lockout.** The provider lockout policy is off by default. Deployments
  must configure it (`/admin/v1/policies/password/lockout`) *and* keep SaaS-OS
  per-account rate limiting. The locked state must not be disclosed.
- **R6 — WebAuthn.** SaaS-OS supplies the RP ID from its own configuration
  (never from the request), validates `clientDataJSON.origin` equals the
  public origin, and requires `userVerified` for passkey-only login. Hosted-UI
  passkeys need re-enrollment.
- **R7 — Base URI.** Set `login_v2.base_uri` to a product-owned path that is
  harmless if a browser ever lands on it (for example, the product login
  page), since ZITADEL does not validate it.

### 12.4 Still unresolved (NOT VERIFIED)

- Exact authorization-code lifetime (single use is verified).
- Response-timing differences between unknown, known, and locked accounts.
- Real-browser end-to-end run (software authenticator only), and passkey `amr`
  through a full callback (source only).
- Behavior on the production topology (`id.<domain>` plus `app.<domain>`, TLS)
  rather than localhost.
- OTP via SMS or email, `sendLink` recovery, and `userLoginMustBeDomain`
  login names.
- Maintenance of the custom role mapping across ZITADEL upgrades (R1).

### 12.5 Overall

The approved architecture is **technically viable** on ZITADEL v4.19.0. A
browser never needs to contact ZITADEL, and the existing SaaS-OS OIDC
validation stays authoritative. Implementation may proceed **only with
refinements R1 to R7 adopted**. R1 and R2 are security-critical: without them,
the login-client credential is an instance-takeover and user-impersonation
credential.

---

## 13. Implementation status (Phases 2–3)

- **Current:** Hosted OIDC (`saas_os/api/auth/routes.py`) remains the only
  implemented login and the production path. Embedded login is **not**
  operational, and ZITADEL is not connected to the embedded boundary.
- **Phase 2 (implemented):** the provider-neutral contract in
  `saas_os/core/identity/embedded_login.py` and the error taxonomy in
  `saas_os/core/identity/errors.py`. The implemented names differ slightly from
  §5.1's sketch (`start`/`complete` on the base protocol, with capabilities as
  separate optional protocols); ADR-0026's Phase 2 note is authoritative.
- **Phase 3 (implemented):** server-side transaction persistence and
  lifecycle in `core.embedded_login_transactions` (migration `61a7ad139d7f`):
  - provider state encrypted with `saas_os.core.crypto` and bound to its row;
  - constant-time browser binding;
  - expiry enforced per operation;
  - single-use completion under a row lock;
  - repository-level cleanup.

  See ADR-0026's Phase 3 note.
- **Phase 4A (implemented):** the ZITADEL adapter foundation
  (`saas_os/core/identity/zitadel_login.py`: start, password, completion,
  termination), which applies §12.3:
  - R1: a dedicated least-privilege role, never `IAM_LOGIN_CLIENT` or the
    bootstrap credential;
  - R3: a bounded provider session;
  - R4: collapsed failures;
  - R7: the authorize redirect is never followed.

  It is not reachable from any route. See ADR-0026's Phase 4A note.
- **Future:** embedded routes and orchestration (Phase 5), session linkage
  and the `amr` policy (Phase 6, R2), MFA/passkeys (7, R6), recovery (8),
  security testing (9), and end-to-end validation (10). Also future:
  lockout-policy configuration (R5) and base-URI configuration (R7) in
  deployments.
