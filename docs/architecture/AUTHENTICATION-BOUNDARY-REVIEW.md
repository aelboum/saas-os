# Authentication Boundary Review — Product-Owned Branded Login

**Status:** Review. **Outcome (human direction, 2026-09-25):**

| | |
|---|---|
| Current accepted architecture | Identity-provider-owned authentication, with SaaS-OS as an OIDC relying party (ADR-0005). |
| SaaS-OS-mediated credential authentication (Session API) | **NOT ACCEPTED** |
| ADR-0024 | **DRAFT — NOT ACCEPTED** |
| Next architectural investigation | Whether a provider-owned, customized Login V2 on a product-controlled domain can satisfy the branded, invisible-provider UX (§10). |
| Implementation | **NOT AUTHORIZED** |

**Question.** Should SaaS-OS support a product-owned, branded login backed by
an external identity provider such as ZITADEL? Specifically, should SaaS-OS
become involved in credential authentication (for example through ZITADEL's
Session API), and what would that change?

---

## 1. Repository state reviewed

| Item | Value |
|---|---|
| Branch | `claude/current-repo-m3uwm5` |
| HEAD | `04e29675968dbf972228ae80504aea6a3e2a357e` (`feat: generalize local zitadel bootstrap tooling`) |
| Committed architecture | ADR-0005 (Accepted), ADR-0023 (**Draft**), `docs/SECURITY.md` §2, `core/identity/provider.py::IdentityProvider` |

**The working tree differs materially from HEAD.** At the time of this
review, it contains **uncommitted** changes that are not part of the
committed architecture:

- `docs/ADR/0024-product-owned-embedded-login-provider-neutral-boundary.md`
  (untracked). It never had a recorded human acceptance, and its header now
  says **DRAFT — NOT ACCEPTED** (previously it wrongly said "Accepted").
- `docs/architecture/PRODUCT-OWNED-AUTHENTICATION-ARCHITECTURE.md`
  (untracked), which is an investigation plus a live verification spike.
- Amendment notes in ADR-0005, ADR-0023, and `docs/SECURITY.md` that
  presented ADR-0024 as approved. They were never committed, and those three
  files have been returned to their committed (HEAD) text. The
  `docs/ADR/README.md` index row for ADR-0024 now says DRAFT — NOT ACCEPTED.
- Uncommitted runtime code, **since removed without being committed**
  (2026-09-25 cleanup), so none of it exists in the repository:
  - `core/identity/embedded_login.py`
  - `core/identity/embedded_login_transactions.py`
  - `core/identity/zitadel_login.py`, a ZITADEL Session API adapter
  - migration `61a7ad139d7f`
  - an import-linter contract
  - tests

This review treats **committed HEAD as authoritative**. The uncommitted
material is treated as unapproved proposal and prototype. Its factual
findings about ZITADEL v4.19.0 behavior are cited as evidence where relevant,
labeled *(uncommitted spike evidence)*, because they come from the
investigation document rather than committed, reviewed material. This review
itself did not modify, delete, or endorse any of it. The prototype code was
later removed in a separate cleanup; the documents are kept.

---

## 2. Existing architecture (committed HEAD)

### 2.1 Responsibility split

| Concern | Owner | Evidence |
|---|---|---|
| Credential verification (passwords, MFA, WebAuthn, lockout) | **Identity provider** | ADR-0005 Decision: "credential verification, MFA, password/SSO handling is delegated to ZITADEL. The platform does not store passwords or implement its own login form logic." SECURITY.md §2 repeats this. ADR-0023 §4 lists credential authentication, MFA, and WebAuthn under the identity provider. |
| Login UI | **Identity provider** (hosted) | `api/auth/routes.py`: `GET /auth/login` redirects the browser to the discovered `authorization_endpoint`. |
| Protocol boundary | **OIDC Authorization Code + PKCE (S256)** | `core/identity/oidc.py`, `core/identity/login_transactions.py`. |
| Identity result | **Validated ID token** (RS256/ES256 via JWKS; iss, aud, exp, sub, nonce) | `core/identity/oidc.py::validate_id_token`. |
| Identity mapping | **SaaS-OS**: `(issuer, subject)` to `core.users` | ADR-0023 §5; `core/identity/service.py`. |
| Application session | **SaaS-OS**: opaque, SHA-256 at rest, HttpOnly cookie | `core/identity/sessions.py`; ADR-0023 §6. |
| Tenancy and authorization | **SaaS-OS**: membership plus `core/rbac` | ADR-0005, ADR-0023 §4. |

### 2.2 `IdentityProvider` boundary (HEAD)

`core/identity/provider.py::IdentityProvider` is the only identity protocol
at HEAD. It has five operations: `get_config`, `get_flow_endpoints`,
`build_authorization_url`, `exchange_authorization_code`, and
`validate_id_token`.

Its docstring explicitly excludes "password management, MFA, account
linking, user administration, refresh tokens, provider-side logout, provider
management APIs". `OIDCIdentityProvider` is pure standards OIDC, with nothing
ZITADEL-specific.

### 2.3 Answers to the required questions (HEAD)

1. **What SaaS-OS owns:** the relying-party role (authorize redirect, code
   exchange, token validation), identity mapping, application sessions,
   tenancy, and authorization.
2. **What the identity provider owns:** all credential verification, the
   login UI, MFA, WebAuthn, recovery, and lockout.
3. **ADR-0023 proposes:** self-hosted ZITADEL, a provider-neutral
   configuration boundary, a private-network production topology, and ZITADEL
   as infrastructure only. Products integrate with SaaS-OS identity, never
   with ZITADEL.
4. **ADR-0023 explicitly excludes (§14):** a custom authentication protocol, a
   custom password store, a new identity database owned by SaaS-OS, direct
   product-to-ZITADEL integrations, a ZITADEL SDK dependency, and
   refresh-token persistence. §15 records that a "zero browser visibility"
   design "would require a fundamentally different authentication mechanism
   and would undermine the OIDC architecture."
5. **Does any accepted ADR authorize product-owned credential
   authentication?** **No.** ADR-0005, the only accepted identity ADR,
   states the opposite. ADR-0023 is Draft. ADR-0024 exists only uncommitted.
6. **Does any committed code path require SaaS-OS to receive a user's
   plaintext password?** **No.** Every `password` match in committed
   `core/`, `api/` and `infra/` code is database, SMTP, or redaction
   configuration.
7. **May SaaS-OS hold an external-provider bearer session token under the
   committed architecture?** **No such path exists.** The backend holds only
   an optional OIDC client secret and a transiently handled ID token, which
   is never persisted. The only privileged ZITADEL credential in the
   committed topology (the bootstrap `IAM_OWNER` PAT) lives on the
   `zitadel-bootstrap` volume and "is never given to `backend`"
   (`docs/DEPLOYMENT-ARCHITECTURE.md`, ADR-0023).
8. **Does ZITADEL-specific authentication logic exist?** **Not at HEAD.**
   ZITADEL-specific code at HEAD is provisioning and operations only: the
   local and production bootstrap and the backup drill. An uncommitted
   prototype adapter (`core/identity/zitadel_login.py`) existed briefly in the
   working tree and has been removed.

### 2.4 ADR-0023 status

- **Status:** Draft — "No implementation is authorized by this draft alone"
  (§19).
- **Relevant decision:** provider-neutral identity with ZITADEL as invisible
  infrastructure. "Invisible" is defined in §9 as no ZITADEL branding, no
  third-party hostname, and no product-code coupling. It is explicitly **not**
  a single unchanging hostname, and not elimination of the OIDC redirect.
- **Relevant non-goals:** §14, listed above.
- **Implementation authorization:** none for anything beyond what it
  describes, and it is itself not accepted.
- **Embedded or product-owned credential authentication:** not authorized.
  §15 treats it as a different mechanism that would undermine the OIDC
  architecture.

---

## 3. The proposed capability versus the existing model

```text
Proposed (B)                              Existing (A)
Product (branded UI, product origin)      Product
   │ credentials                             │ redirect
   ▼                                         ▼
SaaS-OS  ── credential authentication     Identity provider (hosted login)
   │         (server-to-server)              │ OIDC code
   ▼                                         ▼
ZITADEL Session API                       SaaS-OS (code exchange, ID-token
   │ OIDC code (CreateCallback)                 validation, session)
   ▼
SaaS-OS (same code exchange / validation)
```

The difference is not cosmetic. In (B), SaaS-OS moves from **relying party**
to **credential-handling intermediary**. It receives the user's secrets, and
it holds a credential that can drive the provider's authentication on behalf
of any user.

---

## 4. Security analysis

### 4.1 Plaintext credentials

- **Would SaaS-OS receive the password?** Yes, under (B). The browser posts
  it to a SaaS-OS endpoint, and SaaS-OS forwards it to the provider.
- **Where it would exist:**
  - request parsing (FastAPI/Starlette request body buffers);
  - the handler's local variables;
  - the provider-client call, including httpx request construction;
  - process memory until garbage-collected.

  Python offers no reliable memory zeroing.
- **Accidental exposure paths:**
  - exception tracebacks that capture locals (`logger.exception`, error
    middleware, debuggers);
  - request-body logging, if anyone enables it;
  - OpenTelemetry instrumentation that records request attributes;
  - httpx debug logging;
  - crash dumps;
  - future "log the failed request" diagnostics.

  ADR-0020 redacts only by *key name* in structured `extra` fields, and
  explicitly does **not** cover message strings or exception tracebacks. A
  password in a traceback local is outside its protection.
- **Persistence:** no persistence is *required*. Accidental persistence
  (logs, APM, error-tracking services) becomes a standing risk that does not
  exist today.
- **Security boundary change:** yes. SaaS-OS and every product deployment
  become in scope for credential-handling controls: TLS termination at the
  proxy, log hygiene, APM configuration, and memory-inspection exposure.
  Today these apply only to the provider.

### 4.2 Provider bearer session token

*(Uncommitted spike evidence, ZITADEL v4.19.0.)* A Session API session token
works as a **bearer credential for ZITADEL's own APIs as that user**. Tokens
rotate on every session update, default to **no expiry**, and stop working
immediately when the session is deleted.

Under (B):
- **Storage:** needed across steps (password, then second factor) and until
  completion. It must be encrypted at rest (`core.crypto`, ADR-0019) and
  never reach a browser.
- **Lifetime:** must be set explicitly on every session, because the
  provider default is unlimited.
- **Revocation:** SaaS-OS must delete provider sessions on logout and
  failure, and gains lifecycle duties for a second session system.
- **Rotation:** every step invalidates the previous token, so stored state
  must be replaced atomically.
- **Compromise impact:** a leaked session token lets its holder act as the
  user against the provider's self-service APIs, within the provider's own
  MFA policy.
- **Leak paths:** the same as §4.1, plus serialization of server-side state.
  The uncommitted prototype found that `dataclasses.asdict()` copied a
  plaintext provider token out of a nested value, which shows how easily
  this class of leak occurs.

### 4.3 The login-client credential (new high-value secret)

(B) requires the backend to hold a provider credential with at least
session-write and session-link permissions.

*(Uncommitted spike evidence.)* ZITADEL's `CreateCallback` (which finalizes
the OIDC request) accepted a session in which **no credential had been
verified**, and it produced a valid, correctly signed ID token for that user.
The login-client credential alone is therefore sufficient to mint an
authorization code for **any user** in its scope.

Consequences:
- This secret becomes an **impersonation credential** stored in the SaaS-OS
  backend, a component that holds no such power today.
- The only SaaS-OS-side mitigation found is to reject ID tokens whose `amr`
  claim lacks a verified credential factor. That becomes a
  **security-critical** control, not defense in depth.
- It protects SaaS-OS, but **not other applications on the same ZITADEL
  instance**. A stolen login-client credential could mint codes for any
  application that trusts the instance.

### 4.4 MFA

- **Existing:** the provider decides and enforces MFA during hosted login.
  SaaS-OS makes no MFA decision.
- **Under (B):** *(uncommitted spike evidence)* `CreateCallback` does **not**
  enforce the provider's MFA policy. A password-only session was accepted
  with `forceMfa=true`.
- SaaS-OS would therefore become **responsible for deciding whether
  authentication satisfies MFA policy**: reading provider policy, driving
  second-factor steps, and verifying the result from `amr`. That reverses
  ADR-0005's split.

### 4.5 WebAuthn

Under (B), the browser ceremony runs on the product origin, so SaaS-OS
becomes responsible for:

- the **RP ID** (choosing it, which binds every enrolled passkey to that
  domain);
- **origin validation**: *(uncommitted spike evidence)* the provider accepted
  an assertion whose `clientDataJSON.origin` was a foreign origin, so origin
  checking must be done by SaaS-OS;
- the **challenge lifecycle** (bound to the login transaction);
- relaying authenticator data, and **enrollment** (registration flows).

Assertion signature verification would remain with the provider. Existing
passkeys enrolled through the hosted UI are bound to the provider's domain
and would not work on the product origin.

### 4.6 Recovery

*(Uncommitted spike evidence.)* Requesting a password reset needs the
provider permission `user.write`, which also allows deactivating users.
Completing a reset with a one-time code does not need it. Under (B), SaaS-OS
would need either a **second, broader credential** for recovery or would
widen the login credential. It would also have to deliver reset codes
(through `core/email`) and treat them as credentials.

### 4.7 Account enumeration

*(Uncommitted spike evidence.)* The Session API distinguishes three outcomes:

- unknown user: 404 "User could not be found";
- wrong password: 400 "Password is invalid";
- locked account: 400 "Errors.User.NotActive".

The provider setting `ignoreUnknownUsernames` has no effect on this API.
Under (B), SaaS-OS must collapse all three into one indistinguishable
response and equalize timing (not measured). Today the provider's hosted UI
owns this problem.

### 4.8 Credential authority

Under (B), the provider remains the **credential store and verifier**.
SaaS-OS becomes a **credential-handling party**: it sees credentials,
orchestrates factor sequencing, and holds a credential that can complete
authentication without them.

It is not the credential *authority* in the storage sense, but it becomes
partially responsible for credential *authentication*. That contradicts
ADR-0005's Decision and SECURITY.md §2 as committed.

---

## 5. Least-privilege analysis (Option B)

The operation-to-permission mapping below is *(uncommitted spike evidence,
from ZITADEL v4.19.0 source and live tests)*.

| Operation | ZITADEL permission |
|---|---|
| Create or update a session (password, OTP, WebAuthn checks) | `session.write` |
| Read a session or auth request | `session.read` |
| Finalize an OIDC auth request (`CreateCallback`) | `session.link` |
| Delete a session (logout) | `session.delete` |
| Read login policy, list a user's factors | `policy.read`, `iam.policy.read`, `user.read` |
| **Request** a password reset | `user.write` (broad: can also deactivate users) |
| **Complete** a reset with its code | none beyond the login role |

Findings:
- The built-in `IAM_LOGIN_CLIENT` role is **not least-privileged**. It
  includes `iam.member.write`, and a live test granted `IAM_OWNER` with it.
- A custom role limited to the rows above, excluding `user.write`, was shown
  to work and to deny escalation. It requires overriding ZITADEL's runtime
  role mapping and reconciling it on every ZITADEL upgrade.
- **No narrower set** than `session.write` + `session.link` exists for the
  core flow. Together those two are inherently the impersonation capability
  described in §4.3.
- Recovery **can** be separated into a distinct credential and role.
- Runtime and bootstrap/admin credentials **can** stay fully separate. This
  would be a **new** runtime secret in the backend, where the committed
  architecture has none.

---

## 6. Alternatives (not ranked)

### Option A — Identity-provider-owned authentication

```text
Product-branded entry ──▶ Provider authentication ──▶ OIDC ──▶ SaaS-OS session
```

- **Credential boundary:** unchanged. SaaS-OS never sees credentials, and the
  provider enforces MFA, WebAuthn, lockout, and enumeration handling.
- **Branding reachable without moving credentials into SaaS-OS:**
  - Hosted login appearance: ZITADEL label and branding policy (logo,
    colors, fonts, custom texts, hiding the ZITADEL watermark). *Not
    verified in this review.*
  - An operator-controlled identity hostname (`id.<product-domain>`, ADR-0023
    §9): no third-party or ZITADEL-branded hostname, but the host changes
    during login.
  - A variant: the provider's own Login V2 application, self-hosted, themed,
    and possibly routed under the product's own origin. This moves
    credential handling into a **provider-maintained component outside
    SaaS-OS code**, with the same login-client credential concerns as §4.3
    and §5, but held by that component rather than the SaaS-OS backend.
    Same-origin routing of that application is **not verified**.
- **Unmet requirements:** "browser never leaves the product origin" and "no
  provider-rendered UI" are met only by the Login V2 variant, if its
  routing works; otherwise they are not met.

### Option B — SaaS-OS-mediated credential authentication (Session API)

```text
Product login ──▶ SaaS-OS ──▶ ZITADEL Session API ──▶ CreateCallback ──▶ existing OIDC validation
```

- **Meets:** product-owned UI, browser on the product origin, no visible
  provider (these are *uncommitted spike evidence* that it is technically
  feasible on v4.19.0).
- **Adds to SaaS-OS:**
  - plaintext-credential handling (§4.1);
  - provider bearer tokens (§4.2);
  - a new impersonation-capable runtime secret (§4.3);
  - responsibility for MFA policy and `amr` verification (§4.4);
  - WebAuthn RP ID and origin control (§4.5);
  - a second, broader credential for recovery (§4.6);
  - enumeration collapsing (§4.7);
  - a custom role mapping to maintain across provider upgrades (§5);
  - a second session lifecycle to manage.
- **Conflicts** with ADR-0005's accepted Decision, SECURITY.md §2 as
  committed, and ADR-0023 §15. It is compatible with ADR-0023 §14's literal
  non-goals: it needs no custom password store and no custom protocol,
  because the flow still ends in standard OIDC code redemption.

### Option C — Provider-neutral, product-owned authentication boundary

A future abstraction under which products own the login UI while SaaS-OS is
**not** the credential authority. For example, SaaS-OS defines the UX
contract, while credential handling sits in a separately deployed,
separately secured component (provider-maintained or dedicated), and SaaS-OS
remains a pure OIDC relying party.

Consequences and unresolved decisions:
- Who deploys, secures, and audits the credential-handling component, and
  whether it is per-product or shared.
- Whether that component's provider credential (§4.3) is acceptable anywhere.
  The impersonation property does not disappear by relocating it.
- How provider replacement works: every provider exposes different login APIs,
  so "provider-neutral" applies to the *product contract*, not the adapter.
- Whether products need this at all, or whether Option A branding suffices.

Not designed here.

---

## 7. Relationship to downstream products

A downstream product may require:

- product-branded login;
- no visible ZITADEL hostname or branding;
- the browser staying on the product origin.

These are **requirements to evaluate**, not authorization. Nothing in any
downstream repository, and nothing in this repository's uncommitted working
tree, constitutes an approved SaaS-OS architecture decision. Committed
ADR-0023 §9 already satisfies "no ZITADEL branding or vendor hostname", but
explicitly not "never leaves the origin".

---

## 8. Open questions for the human decision

1. Is **"the browser never leaves the product origin"** a hard requirement,
   or is an operator-controlled identity subdomain (ADR-0023 §9) with
   provider-side branding acceptable?
2. Is it acceptable for SaaS-OS (or any SaaS-OS-deployed component) to
   **receive plaintext user credentials**?
3. Is it acceptable to hold a **login-client credential that can mint
   authorization codes for any user**, protected mainly by a SaaS-OS-side
   `amr` check?
4. Should SaaS-OS take on **MFA-policy enforcement** that the provider does
   not perform in this flow?
5. Is a **custom provider role mapping**, maintained across provider
   upgrades, an acceptable operational burden?
6. Has Option A branding (label policy, custom texts, watermark removal) or
   the Login V2 variant been evaluated against the product's actual UX
   requirements?
7. **What is the status of the uncommitted ADR-0024 and its prototype
   implementation** (§1)? It should be either accepted by a human and
   committed, or marked not accepted, before further work proceeds on either
   path.

---

## 9. Conclusion of this review

- **Outcome (human direction, 2026-09-25):** SaaS-OS-mediated credential
  authentication (Option B in §6, Option C in §10) is **NOT ACCEPTED**.
  ADR-0024 is **DRAFT — NOT ACCEPTED**.
- The accepted architecture is unchanged: provider-owned authentication, with
  SaaS-OS as a pure OIDC relying party (ADR-0005, `docs/SECURITY.md` §2). ADR-0023
  remains Draft and unchanged.
- **Next investigation:** provider-owned, customized Login V2 on a
  product-controlled domain (§10).
- **Implementation:** NOT AUTHORIZED.

---

## 10. Provider-owned branded login: investigation (2026-09-25)

**Question.** Can the product get a branded, invisible-provider login while
credential handling stays entirely inside ZITADEL, and SaaS-OS remains a pure
OIDC relying party?

**Pinned version.** `ghcr.io/zitadel/zitadel:v4.19.0` (`docker-compose.yml:166`,
`docker-compose.prod.yml:378`). The repository does not deploy the Login V2
application today. The local and production compose files set
`ZITADEL_DEFAULTINSTANCE_FEATURES_LOGINV2_REQUIRED=false`, so the hosted v1 UI
bundled in the main image is what runs.

**Evidence.**

- **Source:** the ZITADEL repository at tag `v4.19.0` (git-verified tag),
  `apps/login` (the Login V2 Next.js application):
  - `next-env-vars.d.ts`, `next.config.mjs`;
  - `src/lib/service-url.ts`, `src/lib/server/host.ts`;
  - `src/lib/server/session.ts`, `src/lib/server/passkeys.ts`;
  - `src/lib/cookies.ts`, `src/lib/oidc.ts`, `src/lib/mfa-helper.ts`;
  - `src/i18n/request.ts`, `src/components/dynamic-theme.tsx`;
  - `locales/en.json`, `THEME_CUSTOMIZATION.md`, `project.json`.
- **ZITADEL server source** (v4.19.0): `internal/api/oidc/auth_request.go`, and
  application `login_version.login_v2.base_uri`.
- **Live** facts are from the earlier spike and are labelled.
- **Nothing in this section was verified live with the Login V2 application
  itself.** The Docker daemon is unavailable in this environment, and zitadel.com
  documentation is unreachable through the network proxy.

### 10.1 Findings

**Login V2 is a separate application.**
- It is a separate Next.js application (`apps/login`), built as its own
  image, `zitadel/zitadel-login` (`project.json`).
- ZITADEL redirects a login-v2 application's authorize request to
  `<base_uri>/login?authRequest=V2_<id>`. That shape was verified live; the
  per-application `base_uri` was verified live and is not validated by
  ZITADEL.
- Login V2 then drives authentication through ZITADEL's session and OIDC APIs,
  server-side (`src/lib/oidc.ts` calls `createCallback`).

**Custom Login UI / self-hosting (source).**
- The base path is configurable through `NEXT_PUBLIC_BASE_PATH` (for example
  `/ui/v2/login`). It is a build-time Next.js setting.
- The app reaches ZITADEL through `ZITADEL_API_URL`, authenticating with
  `ZITADEL_SERVICE_USER_TOKEN` (or `_FILE`) or a login-client JWT key
  (`ZITADEL_LOGINCLIENT_KEYFILE`).
- `CUSTOM_REQUEST_HEADERS` lets it reach ZITADEL at an internal address.

**Product-controlled hostname (source).**
- Login V2 separates the **instance host** (which ZITADEL instance to call:
  `x-zitadel-instance-host` / `x-zitadel-forward-host` / `Host`) from the
  **public host** (in the source's own words, "the public host that the user
  sees", example `accounts.company.com`: `x-zitadel-public-host` /
  `x-forwarded-host` / `Host`).
- The design therefore supports serving the login UI on a hostname other than
  ZITADEL's own.
- **NOT VERIFIED LIVE.**

**Browser hostname path (source plus earlier live evidence).** Standard OIDC
still has the browser navigate to the **issuer's** authorize endpoint. That is
a redirect only, with no page rendered, but it is visible in network tools and
possibly briefly in the address bar. ADR-0023 §9 (verified against ZITADEL's
reverse-proxy model) records that ZITADEL cannot be path-prefixed under the
product domain. It needs its own hostname.

This gives the following topology:
- `app.<domain>`: the product;
- `accounts.<domain>`, an operator-controlled name: ZITADEL at the root, with
  Login V2 at a base path (ZITADEL's own reference layout routes
  `/ui/v2/login` to the login app);
- an alternative: Login V2 under a path on `app.<domain>`, with only the
  authorize hop touching the issuer host. **NOT VERIFIED.**

**Branding (source).**
- Logo, colors and font come from ZITADEL branding settings
  (`getBrandingSettings`: light/dark logo, colors, font URL).
- Layout, roundness, spacing, appearance and background image come from
  `NEXT_PUBLIC_THEME_*` build settings.
- **Texts** come from locale defaults, deep-merged with ZITADEL's stored
  "hosted login translation" custom texts, which override them without a
  fork.
- **Page structure** is fixed by the application. Changing it means
  forking or maintaining a customized build.

**Residual provider branding (source).**
- No "powered by" or watermark rendering was found in Login V2.
- The `ZitadelLogo` component exists but is not rendered anywhere.
- **Default** texts name the provider: the page `title` "Login with Zitadel",
  "Create your Zitadel account", and the consent disclaimer ("…{appName} and
  Zitadel…").
- These must be overridden through custom texts for **every enabled locale**.
  Whether *every* user-visible string can be overridden this way is **NOT
  VERIFIED**.
- Emails sent by ZITADEL (verification, password reset) use ZITADEL
  notification templates and SMTP configuration, which is a separate branding
  surface. **NOT VERIFIED** for v4.19.0.

**Cookies and session boundary (source).**
- Login V2 stores ZITADEL session ids and tokens in its own `sessions` cookie:
  HttpOnly, `Secure` in production, no `Domain` attribute, so **host-only** on
  the login host.
- It is never sent to the product host, and SaaS-OS never sees it.
- SaaS-OS keeps its own session cookie on the product host (unchanged).

**Credential boundary (source).**
- Passwords, MFA, passkeys and recovery are handled by Login V2, calling
  ZITADEL.
- The browser posts credentials to the Login V2 application, **not to
  SaaS-OS**. SaaS-OS receives only the OIDC authorization code at its existing
  callback.
- The login application needs a service credential with login-client
  permissions. The earlier spike showed that the built-in `IAM_LOGIN_CLIENT`
  role is over-privileged, and that login-client permissions can mint codes for
  any user (§4.3). That credential sits in the **provider-owned login
  component, not in SaaS-OS**, but it still needs least-privilege treatment and
  protection by whoever operates it.

**WebAuthn/passkeys (source).**
- Login V2 sets the WebAuthn domain (RP ID) to the **public hostname** it is
  served on (`session.ts`, `passkeys.ts`), and ZITADEL verifies the
  assertion.
- Passkeys are therefore bound to the login host (for example
  `accounts.<domain>`). Moving the login UI to another hostname later would
  invalidate enrolled passkeys.
- SaaS-OS has no WebAuthn role.

**MFA (source).**
- Login V2 enforces MFA before completing the request (`mfa-helper.ts`:
  `forceMfa` requires MFA for all methods except passkeys; `forceMfaLocalOnly`
  requires it only for password logins).
- Because `CreateCallback` itself enforces no MFA (earlier spike, live),
  enforcement lives in the provider-owned login application, not SaaS-OS.
- An optional SaaS-OS-side `amr` check would be defense in depth. It is not
  proposed here.

**Recovery (source).** Password reset is driven by Login V2 through ZITADEL
(`urlTemplate` / send-link), and ZITADEL delivers the email. SaaS-OS has no
role in it.

**OIDC continuity.** Unchanged:

```text
browser ──▶ SaaS-OS GET /auth/login (state, nonce, PKCE)
        ──▶ issuer /oauth/v2/authorize (redirect only)
        ──▶ Login V2 on the login host (credentials here)
        ──▶ SaaS-OS GET /auth/callback?code&state
        ──▶ existing exchange_authorization_code()
        ──▶ existing validate_id_token()
        ──▶ existing issue_session()
```

No second identity or authentication architecture is introduced, and no
SaaS-OS code changes are implied.

**Operational and upgrade implications.**
- One more deployed component: a Node/Next.js container. It needs:
  - reverse-proxy routes;
  - TLS;
  - a secret (the login service credential);
  - version pinning in lockstep with the ZITADEL server;
  - monitoring.
- Theme settings are build-time, and custom texts are stored in ZITADEL and
  applied per locale.
- A forked or structurally customized UI would need to be rebased on every
  ZITADEL upgrade.
- The login-client role mapping (if narrowed below `IAM_LOGIN_CLIENT`) is a
  runtime configuration override that must be kept in sync with ZITADEL's
  defaults on upgrade (§5).

### 10.2 Requirements assessment (provider-owned Login V2)

| Requirement | Assessment |
|---|---|
| Product branding | **Largely achievable** (logo, colors, font, layout theme, all texts through custom texts; source). Page structure is fixed unless forked. Not verified live. |
| No provider hostname | **Achievable with an operator-controlled hostname** (for example `accounts.<domain>`). **Not achievable** as "the browser never leaves the product origin": the issuer's authorize endpoint needs its own hostname (ADR-0023 §9), so there is at least one redirect hop to it. Serving Login V2 itself under the product origin is plausible by design but **NOT VERIFIED**. |
| No provider branding | **Plausible, not verified.** No watermark was found, but default texts name "Zitadel" and must be overridden per locale; email templates are a separate surface. |
| Credentials remain provider-owned | **Yes.** SaaS-OS receives no password, factor, passkey assertion, recovery code, or provider session token. |
| OIDC continuity | **Yes.** It terminates in the existing SaaS-OS code exchange, ID-token validation, and session issuance, unchanged. |

### 10.3 Options compared (not ranked)

| | A — Hosted provider login (v1 UI, current) | B — Provider-owned customized Login V2 on an operator/product-controlled domain | C — SaaS-OS-mediated credential authentication |
|---|---|---|---|
| Who renders login | ZITADEL (bundled v1 UI) | ZITADEL's Login V2 app, operated by the deployer | Product and SaaS-OS |
| Credentials reach SaaS-OS | No | No | **Yes** |
| Provider bearer tokens in SaaS-OS | No | No (host-only cookie on the login host) | **Yes** |
| MFA enforcement | ZITADEL | Login V2 (provider-owned) | **SaaS-OS** |
| WebAuthn RP ID and origin | ZITADEL | Login V2 public host | **SaaS-OS** |
| Recovery | ZITADEL | Login V2 / ZITADEL | **SaaS-OS, plus a broader credential** |
| Hostname seen | Operator identity subdomain | Operator-controlled login hostname; authorize hop to the issuer host | Product origin only |
| Branding | v1 label policy and texts (not re-verified here) | Theme plus branding plus custom texts (source) | Full (product-built) |
| New components or secrets | None | Login V2 container plus its login-client credential | Login-client credential **in SaaS-OS** |
| SaaS-OS code changes | None | None expected | Large |
| Status | Current | **Candidate for further investigation** | **NOT ACCEPTED** |

### 10.4 Open items before any decision on B

1. Live verification: Login V2 v4.19.0 on an operator-controlled hostname with
   the public/instance host split, end to end with the unchanged SaaS-OS
   callback.
2. Whether every user-visible string (all locales, error pages, emails) can be
   de-branded through configuration alone.
3. Whether serving Login V2 under a path of the product origin works, and what
   that means for passkey RP IDs.
4. Least-privilege login credential for the Login V2 service user (custom role
   versus `IAM_LOGIN_CLIENT`), and who operates and protects it.
5. Whether the remaining authorize redirect hop to the issuer hostname is
   acceptable against the product requirement.

No implementation is authorized by this section.
