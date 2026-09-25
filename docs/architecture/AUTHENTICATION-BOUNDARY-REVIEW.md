# Authentication Boundary Review — Product-Owned Branded Login

**Status:** Review. **Outcome (human direction, 2026-09-25):**

| | |
|---|---|
| Current accepted architecture | Identity-provider-owned authentication, with SaaS-OS as an OIDC relying party (ADR-0005). |
| SaaS-OS-mediated credential authentication (Session API) | **NOT ACCEPTED** |
| ADR-0024 | **DRAFT — NOT ACCEPTED** |
| Next architectural investigation | Whether a provider-owned, customized Login V2 on a product-controlled domain can satisfy the branded, invisible-provider UX (§10). |
| ZITADEL Login V2 product-origin topology | **LIVE VERIFIED** against ZITADEL/Login V2 v4.19.0 (§11). **OFFICIAL ZITADEL SUPPORTABILITY: NOT YET VERIFIED.** Not accepted, not approved, not production-ready: adoption is pending architecture review and supportability verification. |
| Login V2 deployment topology | **DECIDED in ADR-0025 (`docs/ADR/0025-same-origin-zitadel-login-v2-topology.md`): split deployment profiles.** Canonical architecture for **fresh deployments**: `PUBLIC_DOMAIN` + Login V2 (Topology A). Compatibility architecture for **existing deployments**: `IDENTITY_PUBLIC_DOMAIN` + Login V2, keeping the existing issuer and WebAuthn/U2F RP ID. Existing passkeys and U2F credentials cannot be assumed to survive an RP-ID change (§11.3), so there is no automatic issuer or RP-ID migration; any future migration needs its own approved design. **Implementation not yet performed.** The alternatives analysed before the decision remain in §12. |
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
- **Update:** Login V2 v4.19.0 was later verified live (§11). Where §10 and §11
  differ, §11's live results take precedence; §10 is kept as the source-level
  record.

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

> **Update (§11, live):** A third layout was live verified. ZITADEL runs with
> `ExternalDomain` set to the product host, and its root-relative OIDC paths
> are reverse-proxied on that host alongside SaaS-OS. The issuer is then
> `https://app.example.test` itself, so the browser contacts no separate issuer
> hostname. ZITADEL is still served at the root, not path-prefixed, so this
> does not contradict ADR-0023 §9's path-prefix finding. Whether ZITADEL
> officially supports sharing the product hostname this way is **NOT YET
> VERIFIED**.

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
- **Update (§11, live):** that holds only when Login V2 is on a **different**
  host. When Login V2 is served on the product host, the browser sends the
  `sessions` cookie (holding ZITADEL session bearer tokens) to SaaS-OS
  endpoints unless the reverse proxy strips it (§11.4).

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

> **Update (§11, live):** the "No provider hostname" row is superseded. The
> product-origin topology was live verified with no separate issuer hostname,
> but its official supportability is **NOT YET VERIFIED**. The
> "Credentials remain provider-owned" row holds for that topology only while
> the reverse proxy strips provider cookies from SaaS-OS-bound requests
> (§11.4). "No provider branding" was checked live: complete removal is not
> possible with the stock v4.19.0 artifact (§11.7).

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

> **Update (§11, live):** B's "Provider bearer tokens in SaaS-OS: No" holds
> when Login V2 runs on a separate host. When B is served on the product
> origin, it holds only if the reverse proxy strips provider cookies from
> SaaS-OS-bound requests (§11.4). Without stripping, the tokens reached
> SaaS-OS.

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

> **Update (§11):** items 1, 2 (for the pages and email checked), 3 and 5
> were investigated live; see §11 for results and what remains open. Item 4
> is still open.

No implementation is authorized by this section.

---

## 11. Live verification: ZITADEL Login V2 v4.19.0 (2026-09-25)

**Status: LIVE VERIFIED** against ZITADEL v4.19.0 and Login V2 v4.19.0.
**OFFICIAL ZITADEL SUPPORTABILITY: NOT YET VERIFIED.** This section records
observed behaviour. It does not accept, approve or authorize the topology,
and does not claim that it is production-ready or officially supported by
ZITADEL. Production adoption is pending architecture review and supportability
verification. ADR-0023 remains **Draft**; ADR-0024 remains **DRAFT — NOT
ACCEPTED**.

**Evidence levels used in this section:**

| Level | Meaning |
|---|---|
| **LIVE VERIFIED** | Actually observed at runtime. |
| **SOURCE VERIFIED** | Read in the v4.19.0 source, not necessarily exercised. |
| **NOT YET VERIFIED** | Open question. |

**Method.** A disposable environment, since destroyed, ran:
- ZITADEL v4.19.0: the official release binary, checksum-verified against
  the release checksums (the container image could not be pulled);
- Login V2 v4.19.0 (§11.6);
- PostgreSQL 16 and Redis;
- the **real SaaS-OS backend** at repository HEAD, unmodified;
- headless Chromium (Playwright) running the real OIDC flow;
- a disposable TLS CA and disposable test identities.

The test used two instruments:
- **Edge proxy:** a TLS reverse proxy that logged request metadata (method,
  path, cookie *names*, status) and never logged values.
- **Tap:** placed immediately in front of SaaS-OS. It inspected every
  arriving request URL, header and body for known secrets, reporting only
  whether a match was found.

No credentials, tokens, test data or request logs were kept. The repository
was not modified.

### 11.1 Verified product-origin topology (LIVE VERIFIED)

```text
Browser
   │  https://app.example.test   (the only host the browser contacted)
   │
   ├── /login/*                          ─► Login V2 ─► ZITADEL API (server-to-server)
   ├── /oauth/*                          ─► ZITADEL
   ├── /oidc/*                           ─► ZITADEL
   ├── /.well-known/openid-configuration ─► ZITADEL
   ├── /assets/v1/*                      ─► ZITADEL
   │
   └── everything else (/, /auth/*, /app) ─► SaaS-OS
         (the proxy strips provider cookies here, §11.4)
```

| Setting | Value |
|---|---|
| OIDC issuer | `https://app.example.test` |
| ZITADEL | `ExternalDomain=app.example.test` |
| Login V2 | Built with `NEXT_PUBLIC_BASE_PATH=/login` (§11.6); served at `https://app.example.test/login/*` |
| Login V2 → ZITADEL | Forwarded `x-zitadel-instance-host: app.example.test`; login-client service token held by Login V2, never by SaaS-OS |
| SaaS-OS | Unchanged; `OIDC_ISSUER_URL=https://app.example.test` |

Observed browser sequence (password login), all on `app.example.test`:

1. `/auth/login` (SaaS-OS) returns 303.
2. `/oauth/v2/authorize` (ZITADEL) returns 302.
3. `/login/login?authRequest=…` returns 307.
4. `/login/loginname`, then `/login/password` (and `/login/otp/time-based`
   with TOTP) render.
5. `/auth/callback?code&state` (SaaS-OS) returns 303.
6. `/app` renders, and `/auth/me` returns 200.

Redirect-based OIDC always includes a browser navigation to
`<issuer>/oauth/v2/authorize`. That was observed on a separate issuer host in
the earlier spike. Here the issuer *is* the product hostname, so the
navigation stays on `app.example.test`.

### 11.2 Credential boundary (LIVE VERIFIED)

```text
Browser
   │
   ▼
Login V2 / ZITADEL        credentials, MFA, passkeys, password recovery
   │
   ▼
ZITADEL
   │  OIDC authorization code
   ▼
SaaS-OS                   OIDC relying party: code exchange, ID-token validation, own session
```

Credentials remain provider-owned. SaaS-OS receives the OIDC authorization
code, not the user's credentials. It does not receive passwords or TOTP
codes, does not perform WebAuthn, does not own provider credentials, does not
call the ZITADEL Session API for login, and does not store ZITADEL session
bearer tokens. This section does not change the existing credential boundary
(ADR-0005, §2.1).

### 11.3 Flows (LIVE VERIFIED, with provider-cookie stripping enabled)

| Flow | Result |
|---|---|
| Password login | PASS |
| Password + TOTP | PASS |
| Passkey registration | PASS; WebAuthn RP ID = `app.example.test` |
| Passkey login | PASS |
| Password reset | PASS: reset requested in Login V2; email link to `app.example.test/login/password/set`; new password set; subsequent login succeeded |
| SaaS-OS `/auth/me` after login | PASS (200) |
| SaaS-OS session with **all** provider cookies deleted from the browser | PASS: `/app` and `/auth/me` still worked |

Passkeys are bound to the host that serves Login V2. Moving Login V2 to
another host later would invalidate enrolled passkeys.

### 11.4 Provider-cookie boundary (LIVE VERIFIED)

> **Invariant: provider-session cookies MUST NOT be forwarded to SaaS-OS.**
> In a product-origin topology this is the reverse proxy's responsibility and
> part of the security boundary. SaaS-OS does not implement it, and this
> document does not implement it either.

Cookies observed on `app.example.test` (all host-only, `Path=/`):

| Cookie | Owner | Role (LIVE VERIFIED on the tested flows) |
|---|---|---|
| `sessions` | Login V2 | Holds ZITADEL session ids **and session bearer tokens**. Required on `/login/*` for multi-step authentication (TOTP), passkey registration, SSO and provider logout. When stripped on `/login/*`, TOTP failed with "Could not get the context of the user" and passkey registration failed. |
| `fingerprintId` | Login V2 | Not required by the tested flows. Set without `Secure`. |
| `__Host-zitadel.useragent` | ZITADEL | Not required by the tested flows. |
| `saas_os_session` | SaaS-OS | SaaS-OS application session; host-only; contains no provider token. |
| `saas_os_session_login` | SaaS-OS | Short-lived login transaction (path `/auth`). |

The "not required" results apply only to the tested flows in v4.19.0. Do not
generalize them to other ZITADEL/Login V2 versions or untested flows.

None of the three provider cookies was required on `/oauth/*`,
`/oidc/v1/end_session`, `/.well-known/*` or `/assets/v1/*` (LIVE VERIFIED).

**Control: stripping disabled.** The browser sent `sessions`,
`fingerprintId` and `__Host-zitadel.useragent` to SaaS-OS on `/auth/callback`,
`/auth/me` and `/app`. The tap detected real ZITADEL session bearer tokens on
every post-login SaaS-OS request. **The topology is not safe if provider
cookies are allowed through to SaaS-OS.**

**Experiment: stripping enabled on SaaS-OS-bound routes only.** The edge
removed `sessions`, `fingerprintId` and `__Host-zitadel.useragent` from
requests forwarded to SaaS-OS, and left provider routes untouched.

The tap searched every one of the 195 requests SaaS-OS received for:
- the test passwords, including the post-reset password;
- the TOTP codes;
- the reset code;
- the passkey credential IDs;
- all 49 real ZITADEL session tokens learned from provider-side cookies and
  `Set-Cookie` headers.

It found **no matches**.

| Reaches SaaS-OS | Stripping disabled | Stripping enabled |
|---|---|---|
| Password | NO | NO |
| TOTP code | NO | NO |
| WebAuthn material (credential IDs) | NO | NO |
| Reset code | NO | NO |
| ZITADEL session bearer | **YES** | **NO** |
| Cookies received | `__Host-zitadel.useragent`, `fingerprintId`, `sessions`, `saas_os_session`, `saas_os_session_login` | `saas_os_session`, `saas_os_session_login` |

**Callback.** The browser's `GET /auth/callback?code&state` carried
`saas_os_session_login`, `__Host-zitadel.useragent`, `fingerprintId` and
`sessions`. The edge removed the three provider cookies. SaaS-OS received only
`saas_os_session_login`, plus `code` and `state`, with no Authorization header
and no request body. It returned 303 to `/app`.

SaaS-OS application sessions are therefore independent of the provider
session in the tested topology.

### 11.5 Logout: two sessions (LIVE VERIFIED)

There are two sessions: the **SaaS-OS session** and the **ZITADEL/Login V2
provider session**. The results below were the same with and without cookie
stripping.

- **`POST /auth/logout`** ends the SaaS-OS session: 204, then `/auth/me`
  returns 401. It does **not** end the provider session. This is intended:
  SaaS-OS logs out its local application session, and provider logout is out
  of scope for `core/identity/provider.py`. It is not a SaaS-OS defect.
- **Provider logout**, with Login V2 required
  (`LOGINV2_REQUIRED=true`, instance `baseUri` = `https://app.example.test/login`):
  - `/oidc/v1/end_session?client_id&post_logout_redirect_uri&logout_hint`
    redirected (302) to `/login/logout?logout_hint&logout_token=…`.
  - Login V2 terminated the hinted provider session.
  - The next `/auth/login` asked for credentials again.
- **With `LOGINV2_REQUIRED=false`**, `/oidc/v1/end_session` without a hint
  redirected straight back. The provider session **remained active**, and the
  next `/auth/login` completed without a credential prompt (provider SSO).

### 11.6 Login V2 build (LIVE VERIFIED / NOT YET VERIFIED)

- The official Login V2 v4.19.0 release artifact is built for base path
  `/ui/v2/login`. The base path is baked in at build time (SOURCE VERIFIED
  and LIVE VERIFIED).
- The `/login` topology required a source build of v4.19.0 with
  `NEXT_PUBLIC_BASE_PATH=/login`. **Custom `/login` build: LIVE VERIFIED.**
- `buf.build` was unreachable, so that build used locally generated protos.
  Three third-party proto dependencies (googleapis, grpc-gateway,
  protoc-gen-validate) came from GitHub HEAD rather than the commits pinned in
  `buf.lock`. **Production reproducibility of the exact custom build: NOT YET
  VERIFIED.**
- Related (LIVE VERIFIED in the earlier spike):
  - ZITADEL routes an application to Login V2 through its per-app
    `loginV2.baseUri` when `LOGINV2_REQUIRED=false`.
  - When `LOGINV2_REQUIRED=true`, the instance-level `baseUri` overrides the
    per-app value.

### 11.7 Branding (LIVE VERIFIED)

- With stock v4.19.0, visible branding can be largely replaced through
  configuration:
  - logo and colors (label policy);
  - texts (hosted-login translations, set at **both** instance and
    organization level, since org-level lookups did not inherit instance
    overrides);
  - the TOTP issuer (`ZITADEL_SYSTEMDEFAULTS_MULTIFACTORS_OTP_ISSUER`).
- Cookie stripping did not change this result.
- One hard-coded external link target remains on the passkey setup page:
  `https://zitadel.com/docs/guides/manage/user/reg-create-user#with-passwordless`.
  Its text can be overridden; its target cannot.
- **Complete provider branding removal: NO**, not with the stock v4.19.0
  artifact. Login V2 was not modified.

### 11.8 Remaining uncertainties (NOT YET VERIFIED)

1. **Official ZITADEL supportability** of the combination used here:
   - `ExternalDomain` set to the product host;
   - product-origin reverse proxying of ZITADEL paths;
   - Login V2 under a custom base path;
   - the forwarded-host arrangement.
2. **Reproducibility of the custom `/login` build** with the pinned proto
   dependencies.
3. **Untested flows:** external IdP login, self-registration, email
   verification, device authorization, SAML, U2F.
4. **Production reverse-proxy/CDN behaviour** (cookie stripping, header
   handling, caching).
5. **Firefox and Safari** behaviour (only headless Chromium was tested).
6. **Future ZITADEL/Login V2 cookie-name changes.** Stripping by name must
   track them.
7. **WebAuthn assertion bytes** could not be inspected. Only passkey credential
   IDs were checked at the SaaS-OS boundary, although every WebAuthn request
   went to `/login/*`.
8. Least-privilege login credential for the Login V2 service user (§10.4
   item 4).

No implementation is authorized by this section.

---

## 12. Architecture decision pending: Login V2 deployment topology

**Status: PENDING HUMAN ARCHITECTURE REVIEW.** This section documents three
alternatives. It does **not** rank them, recommend one, or make the decision.

**Naming.** "Topology A/B/C" here are **not** the same as "Option A/B/C" in
§6 or §10.3.

**Evidence levels:**
- **OFFICIAL DOCUMENTATION:** ZITADEL's versioned docs at tag `v4.19.0`,
  `apps/docs/content/**`, the source of zitadel.com/docs. zitadel.com itself
  was unreachable during the audit.
- **OFFICIAL SOURCE BEHAVIOR:** ZITADEL source at `v4.19.0`. This is not the
  same as official deployment support.
- **LIVE VERIFIED:** §11 and the earlier Login V2 spike.
- **NOT VERIFIED:** open question.

Documentation paths below are relative to `apps/docs/content/`.

### 12.1 Decision scope

The pending decision is: **which ZITADEL Login V2 deployment topology should
be taken forward for production architecture?**

It is a deployment-boundary decision, not a decision to move credential
ownership into SaaS-OS. In every alternative the following stays invariant:

```text
Browser
   ↓
ZITADEL Login V2        (credentials, MFA, passkeys, recovery)
   ↓
OIDC                    (authorization code, PKCE, ID token)
   ↓
SaaS-OS                 (OIDC relying party)
```

SaaS-OS remains an OIDC relying party. It must not receive:
- passwords;
- TOTP secrets or codes as authentication input;
- passkey private material;
- ZITADEL provider-session bearer tokens.

### 12.2 Common requirements (all topologies)

These are requirements only. Their mechanisms are not designed here.

**Credential boundary.** ZITADEL (with Login V2) remains responsible for:
- password authentication;
- MFA;
- passkeys;
- password recovery;
- the provider session;
- provider logout.

**SaaS-OS boundary.** SaaS-OS owns:
- OIDC relying-party behaviour;
- its own application session;
- tenant authorization;
- application-level logout.

**Cookie boundary.** Provider cookies must never become SaaS-OS application
credentials. Where they can reach SaaS-OS, they must not be forwarded to it
(§11.4).

**OIDC.** Issuer, discovery, JWKS and token validation must stay coherent:
one issuer, consistent with the `iss` claim that SaaS-OS validates.

**WebAuthn.** The final public Login V2 origin must be stable. Passkeys are
bound to the host that serves Login V2 (LIVE VERIFIED; OFFICIAL
DOCUMENTATION: `concepts/features/passkeys.mdx` says "Passkeys are bound to
your domain").

**Production requirements.** The final deployment must have:
- deterministic routing;
- an explicit route inventory;
- a secure cookie boundary;
- a reproducible Login V2 build, if a custom build is used;
- staging tests;
- a documented rollback;
- monitoring;
- an upgrade procedure;
- a version-compatibility procedure (Login V2 and the ZITADEL server).

### 12.3 Topology A: documented same-origin ZITADEL layout

**Architecture.**

```text
<ZITADEL public domain>          (ExternalDomain; the OIDC issuer)
   ├── /ui/v2/login/*        → Login V2
   └── all other paths       → ZITADEL
```

The application would coexist with this routing model on the same domain.
The only application routing ZITADEL documents is reuse of the domain,
outside ZITADEL's own path prefixes (below).

**Officially documented.**
- **Same-origin routing.** "`/ui/v2/login` → Login UI container … All other
  paths → ZITADEL API container". Sources:
  - `self-hosting/manage/reverseproxy/reverse_proxy.mdx` § Login UI routing;
  - `self-hosting/manage/adopt-login-v2.mdx` §1;
  - `self-hosting/deploy/kubernetes/ingress.mdx`;
  - `guides/integrate/login-ui/fork-and-deploy-login-app.mdx` § Same public
    origin.
- **ExternalDomain** is the domain on which end users access ZITADEL
  (`cmd/defaults.yaml`). It serves as the OIDC issuer and the base URL for
  the APIs, the console and the hosted Login UI (`apis/introduction.mdx`
  § Domains).
- **Domain reuse.** "If you run ZITADEL on a Custom Domain, you may want to
  reuse that domain for other applications", followed by ZITADEL's path-prefix
  list (`apis/introduction.mdx` § API path prefixes). The list includes
  `/v2/`, service paths, `/admin/v1/`, `/auth/v1/`, `/management/v1/`,
  `/system/v1/`, `/assets/v1/`, `/oidc/v1/`, `/saml/v2/`, `/oauth/v2/`,
  `/device`, `/.well-known/openid-configuration`, `/openapi/`,
  `/idps/callback`, `/ui/console/`, `/ui/v2/login` and `/ui/login/`.
- **The official Login V2 artifact** is built for `/ui/v2/login` (OFFICIAL
  SOURCE BEHAVIOR: `apps/login/.env`). No custom build is needed for this
  path.

**Live verification.**
- The exact topology was **not** live tested: ZITADEL `ExternalDomain` set to
  the product host, Login V2 at `/ui/v2/login`, and product routes coexisting
  with every documented ZITADEL prefix.
- The earlier spike did serve the **official** artifact at
  `app.example.test/ui/v2/login` and completed a login. In that run the
  issuer was on a separate host (`id.example.test`), so it was not this
  topology.
- The §11 `/login` results do **not** prove `/ui/v2/login` behaviour in this
  arrangement.

**Unknowns (NOT VERIFIED).**
- The full ZITADEL-plus-product coexistence on one domain, end to end.
- How the "all other paths → ZITADEL" rule and the product's own routes are
  reconciled. Official examples give ZITADEL the catch-all.
- Interaction between ZITADEL's documented `/auth/v1/` prefix and SaaS-OS's
  `/auth/*` routes.
- The provider-cookie boundary in this layout (not live tested here).

**Operational implications.**
- ZITADEL occupies its documented URL prefixes on the shared domain, and the
  product must coexist with them.
- Login V2 uses the documented `/ui/v2/login` route.
- Routing ownership (which upstream owns which prefix, and the catch-all)
  must be explicit.
- Provider cookies are set on the shared host, so the cookie boundary (§12.2)
  applies to requests forwarded to SaaS-OS.
- Passkeys are bound to the shared host.

### 12.4 Topology B: documented separate Login V2 domain

**Architecture.**

```text
product.example   (e.g. app.example.test)       → SaaS-OS / product
accounts.example  (e.g. accounts.example.test)  → Login V2
ZITADEL public domain (ExternalDomain; issuer)  → ZITADEL
```

**Officially documented.**
- **Trusted domain.** Register the login domain on the instance: "Trusted
  domains if login is hosted on a separate hostname"
  (`self-hosting/manage/adopt-login-v2.mdx` §3; `login-ui/login-app.mdx`
  § How to setup domains for OIDC). It must use HTTPS.
- **Proxy headers.** "The OIDC Proxy sets `x-zitadel-public-host` (the Login
  app host) … sets `x-zitadel-instance-host` (the instance host)". Sources:
  `login-ui/login-app.mdx` § OIDC Proxy; `login-ui/fork-and-deploy-login-app.mdx`
  § Separate Login domain, which adds "Do not conflate these settings" with
  `CUSTOM_REQUEST_HEADERS`.
- **Configuration.** `InstanceHostHeaders` and `PublicHostHeaders` are
  documented options, defaulting to `x-zitadel-instance-host` and
  `x-zitadel-public-host` (`cmd/defaults.yaml`).
- **Base URL.** A per-application "custom base URL for a separately hosted
  login UI", and an instance-wide `baseUri` that "takes precedence over
  per-app checkboxes" (`self-hosting/manage/adopt-login-v2.mdx` §4).
- **Built-in proxy.** Login V2 includes a Next.js OIDC proxy for
  `/.well-known/`, `/oauth/` and `/oidc/` (`login-ui/login-app.mdx`
  § Architectural Overview). In source (`apps/login/src/proxy.ts`) it also
  covers `/idps/callback/`, `/saml/` and `/assets/`, relative to the app's
  base path (OFFICIAL SOURCE BEHAVIOR).
- **Public-host check.** A public host must equal the instance domain or be
  a trusted domain (OFFICIAL SOURCE BEHAVIOR: `internal/query/instance.go`).

**Live verification** (earlier spike, official `/ui/v2/login` artifact on
`accounts.example.test`, issuer on `id.example.test`).
- LIVE VERIFIED:
  - password login;
  - password + TOTP;
  - passkey registration and login, with RP ID `accounts.example.test`;
  - the SaaS-OS `/auth/callback`, and `/auth/me` returning 200;
  - Login V2 page rendering (loginname, password, password-reset step, MFA
    and passkey setup) and branding;
  - the trusted-domain requirement: without it, requests failed with "public
    domain … not trusted";
  - per-application base URI routing, and the instance `LOGINV2_REQUIRED`
    precedence;
  - logo assets needing `/assets/v1/` routed on the login host.
- The login `sessions` cookie was host-only on `accounts.example.test`
  (browser cookie jar).
- The spike's proxy set `x-zitadel-instance-host` and passed the public host
  through `Host`/`X-Forwarded-Host`. It did not set `x-zitadel-public-host`
  explicitly.

**Unknowns (NOT VERIFIED).**
- No SaaS-OS-side request tap was run in this topology. That provider cookies
  never reach SaaS-OS rests on the host-only cookie jar only.
- Not tested: external IdP, SAML, device authorization, registration, email
  verification and U2F.
- Not tested: a full reset-email-to-login cycle through Login V2, and provider
  logout through Login V2.
- Not tested: production proxy/CDN behaviour, Firefox and Safari, and the
  explicit `x-zitadel-public-host` configuration.

**Operational implications.**
- An additional public hostname for Login V2 needs DNS, TLS and its own
  proxy/ingress routes. ZITADEL's own public domain is required as well.
- The login hostname must be registered as a trusted domain.
- Forwarded-host headers must be configured as documented.
- The browser visits more than one hostname: the product, the issuer (for
  the authorize redirect) and the login host.
- Passkeys are bound to the login hostname.
- Provider cookies are host-only on the login host, separate from the
  product host.

### 12.5 Topology C: current live-tested product-origin `/login`

**Architecture** (as tested, §11.1).

```text
https://app.example.test          ExternalDomain = app.example.test; issuer = https://app.example.test
   ├── /login/*        → Login V2 (custom build, NEXT_PUBLIC_BASE_PATH=/login)
   ├── /oauth/*        → ZITADEL
   ├── /oidc/*         → ZITADEL
   ├── /.well-known/*  → ZITADEL
   ├── /assets/v1/*    → ZITADEL
   └── catch-all       → SaaS-OS   (provider cookies stripped, §11.4)
```

**Live evidence (v4.19.0, §11).**
- These all passed:
  - password login;
  - password + TOTP;
  - passkey registration and login;
  - password reset;
  - the SaaS-OS callback and `/auth/me`;
  - SaaS-OS logout;
  - provider logout (`end_session` plus `logout_hint`, with
    `LOGINV2_REQUIRED=true`).
- Provider cookies were stripped from SaaS-OS-bound requests, and no provider
  session bearer or credential material reached SaaS-OS (195 requests).
- The SaaS-OS session worked independently.
- The WebAuthn RP ID was the Login V2 host (`app.example.test`).
- The browser contacted only `app.example.test`.

**Official supportability: NOT ESTABLISHED.**

**Deviations from the documented layouts:**
1. ZITADEL's `ExternalDomain` is shared with a third application.
2. SaaS-OS owns the catch-all. Documented same-origin layouts give it to
   ZITADEL.
3. Only selected ZITADEL paths are exposed.
4. Login V2 is at `/login`, not the documented `/ui/v2/login`.
5. `x-zitadel-instance-host` is used in a same-origin context. It is
   documented for the separate-login-domain proxy topology.
6. A custom Login V2 build is required.
7. The tested custom build did not follow the documented frozen-lockfile and
   `nx generate` proto-generation process. Its third-party proto
   dependencies came from GitHub HEAD, not `buf.lock`.

**Known operational risks and open questions** (not scored):
- Future ZITADEL route additions under prefixes the product uses or catches.
- Future cookie-name changes in ZITADEL or Login V2. Stripping is by name.
- Login V2 upgrades, and maintaining the custom build as documented by
  ZITADEL's fork guide.
- The risk of running a topology whose official support is not established.
- The interaction between ZITADEL's `/auth/v1/` prefix and SaaS-OS's
  `/auth/*`.
- External IdP (`/idps/callback`), SAML (`/saml/v2/`) and device (`/device`)
  flows, which were neither exposed nor tested.
- Production CDN/proxy behaviour.
- Whether the default login/logout URL overrides used in ZITADEL's official
  compose (`ZITADEL_OIDC_DEFAULTLOGINURLV2`, `ZITADEL_OIDC_DEFAULTLOGOUTURLV2`,
  `ZITADEL_SAML_DEFAULTLOGINURLV2`) are needed for untested flows.

### 12.6 Side-by-side factual comparison

| Dimension | Topology A | Topology B | Topology C |
|---|---|---|---|
| ZITADEL official documentation | Documented layout (`/ui/v2/login` → Login, other paths → ZITADEL); domain reuse by path prefix documented | Documented layout (trusted domain, `x-zitadel-public-host` / `x-zitadel-instance-host`) | Components documented; exact combination not documented |
| Exact topology live-tested | No | Yes (earlier spike; subset of flows; no SaaS-OS-side tap) | Yes (§11; subset of flows; SaaS-OS-side tap) |
| Login V2 hostname/path | ZITADEL/product shared domain, `/ui/v2/login` | Separate login host, official artifact at `/ui/v2/login` | Product host, `/login` |
| ExternalDomain relationship | ExternalDomain = the shared domain | ExternalDomain = ZITADEL's own domain, separate from login and product hosts | ExternalDomain = product host |
| Trusted domain | Not needed when public host = instance domain (source) | Required for the login host (documented; live) | Not needed (public host = instance domain; live) |
| Forwarded host headers | Host preserved / Forwarded (documented) | `x-zitadel-public-host` + `x-zitadel-instance-host` (documented) | `x-zitadel-instance-host` in same-origin use (not documented for this layout) |
| Custom Login V2 build | Not required | Not required | Required (`NEXT_PUBLIC_BASE_PATH=/login`) |
| Browser-visible hostname(s) | One (shared domain) | Product host, issuer host (authorize redirect), login host | One (product host; live) |
| Product route coexistence | Product coexists with all documented ZITADEL prefixes; ZITADEL catch-all in official examples | Product host carries no ZITADEL routes | SaaS-OS catch-all; selected ZITADEL prefixes routed |
| WebAuthn origin | Shared domain | Login host | Product host |
| Provider-cookie boundary | Provider cookies on the shared host; stripping needed for SaaS-OS-bound requests (not live tested) | Provider cookies host-only on the login host (cookie jar; no tap) | Provider cookies on the product host; stripping live verified |
| Remaining verification | Entire topology end to end | Untested flows, SaaS-OS-side tap, production proxy/CDN | Official supportability, reproducible build, route inventory, untested flows, production proxy/CDN |

### 12.7 Human decision questions

These are for the architecture owner and are not answered here.

1. Is official ZITADEL supportability a hard production requirement?
2. Is a separate Login V2 hostname acceptable?
3. Is occupying ZITADEL's documented path namespace on the product origin
   acceptable?
4. Is maintaining a custom Login V2 build acceptable?
5. Is an undocumented but live-verified topology acceptable if ZITADEL
   maintainers confirm it?
6. Which authentication flows must be supported at launch (for example
   external IdP, SAML, device, registration)?
7. Is written confirmation from ZITADEL maintainers required before
   production?
8. What level of proxy/CDN compatibility testing is required before
   acceptance?
9. How many browser-visible hostnames are acceptable to the product
   requirement?

### 12.8 What is not being decided

This analysis does not decide:
- whether ZITADEL or another IdP should be used;
- whether SaaS-OS should own credentials;
- whether an embedded login should be implemented;
- whether the current product-origin topology is approved;
- whether any reverse-proxy implementation should be merged;
- whether Login V2 should be customized;
- whether production deployment should proceed.

ADR-0023 remains **Draft**. ADR-0024 remains **DRAFT — NOT ACCEPTED**. No ADR
is created or changed by this section. **Implementation is not authorized.**
