# ADR-0025: Same-Origin ZITADEL Login V2 on the Product Domain (Topology A)

Status: Accepted and implemented
Date: 2026-09-25 (proposed); accepted 2026-09-25
Supersedes / Superseded by: supersedes **ADR-0023 §9** (the separate identity subdomain) **for fresh deployments only**. **Existing deployments retain ADR-0023 §9's identity-domain topology**, with Login V2 introduced on that domain (Decision 2, revised). ADR-0023's text is unchanged and keeps its historical record; its other sections are unaffected. ADR-0005 is unchanged and authoritative.

> **Accepted and implemented; acceptance is not a production rollout.** The
> human architecture decisions are recorded under Decision (below). The
> architecture described by this ADR has been implemented for the fresh and
> existing deployment profiles described below (commit `86b63d2`). A
> production rollout still requires the rollout/rollback plan (§11).
>
> **Split deployment profiles (Decision 2, revised 2026-09-25):**
> - **Fresh deployments** use Topology A on `${PUBLIC_DOMAIN}`. This is the
>   canonical architecture for new deployments.
> - **Existing deployments** keep `${IDENTITY_PUBLIC_DOMAIN}`, their existing
>   issuer and their existing WebAuthn/U2F RP ID. Login V2 may be introduced
>   on that domain.
>
> **Existing deployments are not automatically migrated from
> `IDENTITY_PUBLIC_DOMAIN` to `PUBLIC_DOMAIN`** (§1a). No automatic issuer,
> RP-ID, passkey or U2F migration is implemented or implied.

## Context

**Production topology before this ADR** (ADR-0023 §9; retained by the
existing-deployment profile, §1a; `Caddyfile`,
`docker-compose.prod.yml`, `deploy/bootstrap_zitadel_production.py`,
`deploy/generate-identity-tls-cert.sh`,
`tests/architecture/test_production_identity_topology.py`,
`scripts/check-docker-prod.sh`):

```text
https://${PUBLIC_DOMAIN}            → SaaS-OS: /auth/*, /v1/* → backend; everything else → frontend
https://${IDENTITY_PUBLIC_DOMAIN}   → ZITADEL v4.19.0 at the root (all paths)
OIDC issuer = https://${IDENTITY_PUBLIC_DOMAIN}   (ZITADEL_EXTERNALDOMAIN)
ZITADEL_DEFAULTINSTANCE_FEATURES_LOGINV2_REQUIRED=false → Login V1
```

Before this ADR's implementation there was no `zitadel-login` service and no
`/ui/v2/login` route.

**Target for fresh deployments (Topology A; accepted and implemented).**
Existing deployments follow the compatibility profile in §1a instead. The login experience stays on the
product hostname. ZITADEL's hosted Login V2 is served at its documented path,
`/ui/v2/login`, on `${PUBLIC_DOMAIN}`:

```text
https://${PUBLIC_DOMAIN}
   ├── /ui/v2/login/*               → ZITADEL Login V2 (official artifact, no custom build)
   ├── ZITADEL path families (§5)   → ZITADEL
   └── SaaS-OS routes               → SaaS-OS frontend/backend
OIDC issuer = https://${PUBLIC_DOMAIN}
```

User-visible flow: `/auth/login` → `/oauth/v2/authorize` → `/ui/v2/login/...`
→ `/auth/callback` → `/app`.

**Evidence levels used in this ADR:**

| Level | Meaning |
|---|---|
| **OFFICIALLY DOCUMENTED** | ZITADEL's versioned docs at tag `v4.19.0` (`apps/docs/content/**`, the source of zitadel.com/docs) or its configuration reference (`cmd/defaults.yaml`). Paths below are relative to `apps/docs/content/` unless stated. |
| **SOURCE BEHAVIOR** | ZITADEL source at `v4.19.0`. This is not the same as official deployment support. |
| **LIVE VERIFIED** | Observed in the disposable spikes recorded in `docs/architecture/AUTHENTICATION-BOUNDARY-REVIEW.md` §11. |
| **ACCEPTED TARGET** | This ADR's accepted architecture. Implemented in commit `86b63d2` for both profiles; not rolled out to production. |

## 1. Decision

The **canonical architecture for fresh deployments** is: **`${PUBLIC_DOMAIN}`
serves same-origin ZITADEL Login V2 at `/ui/v2/login`**. Existing deployments
use the compatibility profile in §1a. In both profiles ZITADEL remains the
identity provider, and SaaS-OS remains an OIDC relying party.

The human decisions that fix the open choices in §3 to §11 are recorded under
Decision (below). Exact configuration values are set in the implementation
phase.

## 1a. Deployment profiles (Decision 2, revised)

| | **Fresh deployments: canonical profile** | **Existing deployments: compatibility profile** |
|---|---|---|
| Topology | Topology A: same-origin Login V2 on `${PUBLIC_DOMAIN}` | ZITADEL stays on `${IDENTITY_PUBLIC_DOMAIN}` (ADR-0023 §9); Login V2 may be introduced there at `/ui/v2/login` |
| Login V2 served from | `https://${PUBLIC_DOMAIN}/ui/v2/login` | `https://${IDENTITY_PUBLIC_DOMAIN}/ui/v2/login` |
| Issuer / `ExternalDomain` | `${PUBLIC_DOMAIN}` | Unchanged: `${IDENTITY_PUBLIC_DOMAIN}` |
| WebAuthn/passkey and U2F RP ID | `${PUBLIC_DOMAIN}` | Unchanged: `${IDENTITY_PUBLIC_DOMAIN}` |
| Existing credentials | None to carry over | Preserved by keeping their RP ID |
| Issuer or identity-mapping migration | Not applicable | **None implied** |
| Credential migration | Not applicable | **None implied** |

**Existing deployments are not automatically migrated from
`IDENTITY_PUBLIC_DOMAIN` to `PUBLIC_DOMAIN`.**

**Why.** The Decision 2 re-review audit found passkey and U2F preservation
across an RP-ID change **BLOCKED** in ZITADEL v4.19.0:
- **SOURCE BEHAVIOR:** ZITADEL stores the RP ID with each WebAuthn token, and
  at login offers only tokens whose stored RP ID matches the requested one
  (`internal/webauthn/webauthn.go`, `wa_converter.go`). Login V2 always
  requests its own serving hostname as the RP ID.
- **OFFICIALLY DOCUMENTED:** existing passkey authentication "can't be used"
  when the login runs on a different domain (`guides/integrate/login/hosted-login.mdx`),
  and passkeys require "the same domain as the legacy auth server"
  (`guides/migrate/users.mdx`).
- No supported migration mechanism was found. Rewriting database rows is not a
  valid workaround, because the authenticator scopes each credential to its
  RP ID.

Existing credentials therefore stay valid only on their original RP ID, which
the compatibility profile keeps.

**Status:**
- **Accepted now:** the split-profile architecture.
- **Implemented (commit `86b63d2`):** the deployment changes for both
  profiles.
- **Deferred:** any migration of an existing deployment from
  `IDENTITY_PUBLIC_DOMAIN` to `PUBLIC_DOMAIN`.

**Future migration requirement.** Such a migration is out of scope for this
ADR. If it is ever wanted, it needs a separate, explicitly approved migration
project, because existing passkey and U2F credentials cannot be assumed to
survive an RP-ID change. That project must cover:
- credential re-enrolment;
- recovery for passwordless users;
- identity-mapping migration (§3);
- user communication;
- audit requirements;
- rollback implications;
- validation of every authentication factor.

## 2. Credential ownership (invariant; ADR-0005 preserved)

```text
Browser ──► ZITADEL Login V2 ──► ZITADEL      credentials, MFA, passkeys/WebAuthn, recovery, provider session
SaaS-OS                                        OIDC relying party: code + PKCE exchange, ID-token validation, own session
```

SaaS-OS must never receive or manage:
- passwords;
- TOTP or other MFA secrets and codes;
- WebAuthn credentials or assertion material;
- provider-session bearer tokens.

ADR-0005's boundary is unchanged: authentication is delegated to ZITADEL, and
SaaS-OS owns authorization, its application session, tenant resolution and
application-level logout.

## 3. Issuer change (fresh deployments only; no issuer migration for existing deployments)

| | Issuer |
|---|---|
| Current | `https://${IDENTITY_PUBLIC_DOMAIN}` |
| Topology A | `https://${PUBLIC_DOMAIN}` (ZITADEL's issuer is its `ExternalDomain`, OFFICIALLY DOCUMENTED: `apis/introduction.mdx` § Domains) |

SaaS-OS maps identities by `(issuer, subject)` (ADR-0023 §5). ADR-0023 already
states that external identity mappings "MAY require an explicit migration
strategy when changing issuer/subject identity". Changing the issuer can
therefore stop existing mappings from matching: a returning user could arrive
as an unmapped identity. It must not be assumed that existing users simply
continue unchanged.

**An explicit migration decision is required before any production rollout.**
It must distinguish:

| Case | Decision needed |
|---|---|
| Fresh deployment, no existing identities | Confirm that no mapping migration is required. |
| Existing deployment with existing users | How `(issuer, subject)` mappings are carried over, re-linked or re-established, and how accounts are protected from takeover or duplication during that. |
| Existing deployment with enrolled passkeys | See §4. |

This ADR does not design the migration.

**Decided (Decisions 1 and 2, revised):**
- Fresh deployments start with issuer `https://${PUBLIC_DOMAIN}`; there are no
  mappings to migrate.
- Existing deployments **keep issuer `https://${IDENTITY_PUBLIC_DOMAIN}`**, so
  their `(issuer, subject)` mappings are unaffected. No issuer migration is
  implied.

This issuer analysis is retained as evidence for any future, separately
approved migration (§1a):
- SaaS-OS supports one configured issuer per deployment. No dual issuer is to
  be introduced.
- An unknown `(issuer, subject)` pair auto-provisions a new user
  (`core/identity/service.py`, `get_or_create_user_for_external_identity`), so
  switching the issuer without a mapping migration would create duplicate,
  membership-less users.

## 4. Passkeys and U2F (decided: RP ID preserved by the existing-deployment profile)

Passkeys are domain-bound:
- OFFICIALLY DOCUMENTED: `concepts/features/passkeys.mdx` ("Passkeys are bound
  to your domain"), `guides/integrate/login-ui/passkey.mdx`, and
  `guides/integrate/login/hosted-login.mdx`.
- SOURCE BEHAVIOR: Login V2 sets the WebAuthn domain to the host that serves it
  (`apps/login/src/lib/server/passkeys.ts`, `session.ts`, `u2f.ts`).
- LIVE VERIFIED: in both tested topologies, the RP ID equalled the Login V2
  host (review doc §11).

Topology A moves the authentication origin from `${IDENTITY_PUBLIC_DOMAIN}` to
`${PUBLIC_DOMAIN}`. Passkeys and U2F keys enrolled under the current identity
domain are **not** expected to work under the new origin, and this ADR makes
no claim that they migrate automatically.

**Validation outcome (Decision 2 re-review audit): BLOCKED.** WebAuthn
credentials are scoped to the RP ID they were registered under, and Login V2
derives the RP ID from the host serving it. ZITADEL v4.19.0 provides no
supported mechanism to keep credentials enrolled under
`${IDENTITY_PUBLIC_DOMAIN}` usable under `${PUBLIC_DOMAIN}` (evidence in §1a).
U2F has the same constraint. As §4 originally required, the decision returned
to human architecture review.

**Decided (Decision 2, revised):** existing deployments keep
`${IDENTITY_PUBLIC_DOMAIN}` as their RP ID, which preserves their existing
passkey/WebAuthn and U2F credentials. With Login V2 served on that same domain,
it requests the same RP ID (SOURCE BEHAVIOR). This was not live tested with
credentials enrolled through Login V1. No credential is migrated. Fresh
deployments enrol credentials under `${PUBLIC_DOMAIN}` from the start.

## 5. Route inventory (decided: full documented inventory)

The route inventory is part of the supportability boundary. It must be decided
explicitly and not left to implementation.

**ZITADEL v4.19.0 documented path families.** OFFICIALLY DOCUMENTED in
`apis/introduction.mdx` § API path prefixes, which explicitly contemplates
reusing the ZITADEL domain for other applications:

| Family | Paths |
|---|---|
| v2 APIs | `/v2/`; `/v2beta/`; gRPC/Connect service paths `/zitadel.<service>.v2.<Service>/` (action, application, authorization, feature, group, idp, instance, oidc, org, project, saml, session, settings, user, webkey) |
| Legacy v1 APIs | `/zitadel.admin.v1.AdminService/`, `/admin/v1/`; `/zitadel.auth.v1.AuthService/`, **`/auth/v1/`**; `/zitadel.management.v1.ManagementService/`, `/management/v1/`; `/zitadel.system.v1.SystemService/`, `/system/v1/`; `/assets/v1/` |
| Standards | `/oidc/v1/`, `/saml/v2/`, `/oauth/v2/`, `/device`, `/.well-known/openid-configuration`, `/openapi/`, `/idps/callback` |
| UIs | `/ui/console/`, `/ui/v2/login` (separate Login container), `/ui/login/` (Login V1) |

That list is documented, but this ADR does not assume it is exhaustive. For
example, ZITADEL also serves `/.well-known/apple-app-site-association` and
`/.well-known/assetlinks.json` for native-app passkeys (OFFICIALLY DOCUMENTED:
`guides/integrate/login/oidc/native-app-links.mdx`). The full route table must
be re-verified against the exact ZITADEL release being deployed.

**Documented routing models** (OFFICIALLY DOCUMENTED):
1. **Same origin with ZITADEL owning the catch-all.** "`/ui/v2/login` → Login
   UI; all other paths → ZITADEL" (`self-hosting/manage/reverseproxy/reverse_proxy.mdx`
   § Login UI routing; `self-hosting/manage/adopt-login-v2.mdx` §1;
   `self-hosting/deploy/kubernetes/ingress.mdx`;
   `guides/integrate/login-ui/fork-and-deploy-login-app.mdx` § Same public
   origin).
2. **Domain reuse.** Another application reuses the domain, with ZITADEL keeping
   its documented prefixes (`apis/introduction.mdx`).

**Existing SaaS-OS routes on `${PUBLIC_DOMAIN}`:**
- the backend's `/auth/*` and `/v1/*` (`Caddyfile` `@backend`; `api/` routers
  `/auth` and `/v1/tenants`);
- the frontend catch-all.

**Collision: SaaS-OS `/auth/*` against ZITADEL `/auth/v1/*`.** SaaS-OS has no
`/auth/v1` route today, but the current `@backend path /auth/*` matcher would
capture ZITADEL's `/auth/v1/*` legacy Auth API. Any accepted inventory must
resolve this explicitly: either SaaS-OS reserves and never uses `/auth/v1/*`,
with the proxy routing it to ZITADEL, or another resolution is chosen and
recorded. Downstream products (ADR-0015/0017) inherit the same reserved
namespace.

**Options considered** (Option A selected; see Decision 3 below):

- **Option A: full documented ZITADEL prefix inventory.** All documented
  ZITADEL path families are routed to ZITADEL on `${PUBLIC_DOMAIN}`, and
  SaaS-OS and product routes are kept out of them, including `/auth/v1/`.
  Consequences:
  - This follows the documented domain-reuse model.
  - ZITADEL's APIs, Management/Admin/System APIs and `/ui/console/` become
    reachable on the product hostname. They are still protected by ZITADEL's
    own authentication, as they are on `${IDENTITY_PUBLIC_DOMAIN}` today.
  - The product namespace permanently excludes those prefixes, and any
    prefixes future ZITADEL releases add.
- **Option B: accepted restricted inventory.** Only a deliberately chosen
  subset of ZITADEL paths is routed; for example, the earlier proposal routed
  `/oauth/*`, `/oidc/*`, `/.well-known/*` and `/assets/v1/*` besides
  `/ui/v2/login`. Consequences:
  - It deviates from both documented models: the application owns the
    catch-all, and ZITADEL paths are only partly exposed.
  - Its official supportability is **not established**.
  - This option is valid only if the human decision explicitly accepts that
    deviation and the flows it excludes (§6).

**Decided (Decision 3): Option A, the full documented ZITADEL v4.19.0 prefix
inventory, for the fresh-deployment profile on `${PUBLIC_DOMAIN}`.** In the
existing-deployment profile, ZITADEL keeps its own domain,
`${IDENTITY_PUBLIC_DOMAIN}`, where the documented same-origin model applies
(`/ui/v2/login` → Login, all other paths → ZITADEL). The product domain
carries no ZITADEL routes in that profile. The architecture follows the documented domain-reuse/same-origin
route model, not a restricted subset. The prefix inventory above is retained
as researched and must be re-verified against the exact deployed release.

**`/auth/*` ownership:**

```text
/auth/login, /auth/callback, /auth/logout, /auth/me   → SaaS-OS
/auth/v1/*                                             → ZITADEL (reserved)
```

`/auth/v1/*` is reserved for ZITADEL. Neither SaaS-OS nor any downstream
product may claim it. Downstream products inherit the full reserved ZITADEL
namespace. Proxy routing that implements this ownership is part of the
implementation phase and is not changed by this ADR.

## 6. External IdP, SAML and device flows

Route exposure determines which flows can work.

| Flow | Routes involved (v4.19.0) | Evidence |
|---|---|---|
| External IdP login (Google, GitHub, OIDC/SAML IdPs, etc.) | `/idps/callback` must be publicly reachable. IdP redirect URLs are configured as `${CUSTOM_DOMAIN}/idps/callback`. | OFFICIALLY DOCUMENTED: `guides/integrate/login/hosted-login.mdx`; `self-hosting/manage/adopt-login-v2.mdx` §3 and §5 ("External IdP redirect / callback URLs for Login V2 paths"). SOURCE BEHAVIOR: Login V2's own OIDC proxy includes `/idps/callback/` (`apps/login/src/proxy.ts`). |
| SAML (ZITADEL as SAML IdP) | `/saml/v2/`; `ZITADEL_SAML_DEFAULTLOGINURLV2` (default `/ui/v2/login/login?samlRequest=`) | OFFICIALLY DOCUMENTED: `apis/introduction.mdx`; `cmd/defaults.yaml` |
| Device authorization | `/oauth/v2/device_authorization`, plus the user-facing `/device` verification page | OFFICIALLY DOCUMENTED: `cmd/defaults.yaml` (`OIDC.CustomEndpoints.DeviceAuth.Path`); `guides/integrate/login/oidc/device-authorization.mdx` (example "browse to https://<instance>/device"). **Conflicting documentation:** `guides/integrate/login/hosted-login.mdx` lists "Device Authorization Grants" as excluded from the first Login V2 implementation, while Login V2 v4.19.0 has a `/device` route (SOURCE BEHAVIOR). Support under Login V2 is **NOT VERIFIED**. |
| Native-app passkeys | `/.well-known/apple-app-site-association`, `/.well-known/assetlinks.json` | OFFICIALLY DOCUMENTED: `guides/integrate/login/oidc/native-app-links.mdx` |

Flows must not be disabled merely to simplify routing. None of these flows was
live-tested in any topology (review doc §11.8). This ADR does not promise that
they work.

**Consequence of Decision 3:** the routes these flows need
(`/idps/callback`, `/saml/v2/`, `/oauth/v2/device_authorization`, `/device`,
and the native-app `/.well-known/*` files) are part of the accepted full
inventory. They are not excluded by routing. Each flow's behaviour under
Topology A is still **NOT VERIFIED**. Which flows are enabled and tested at
launch is part of implementation planning.

## 7. Login V2 credential (decided: system-user JWT; no credential created)

Login V2 authenticates server-to-server to the ZITADEL API. The documented
mechanisms (OFFICIALLY DOCUMENTED: `self-hosting/manage/adopt-login-v2.mdx`
§2, "Login resolves credentials roughly as") are:
1. a **system-user JWT** (`AUDIENCE`, `SYSTEM_USER_ID`,
   `SYSTEM_USER_PRIVATE_KEY` / `_FILE`), whose public key is registered
   under `SystemAPIUsers` with `IAM_LOGIN_CLIENT` membership. It is
   "recommended on recent Helm" (chart ≥ v10 with ZITADEL ≥ v4.14);
2. **`ZITADEL_LOGINCLIENT_KEYFILE`**, a JWT key with subject `login-client`;
3. **a service-user PAT** (`ZITADEL_SERVICE_USER_TOKEN` / `_FILE`) for a
   machine user holding `IAM_LOGIN_CLIENT` (`self-hosting/manage/login-client`).
   For existing instances "the setup job does not auto-create the login
   client".

**Related facts:**
- The built-in `IAM_LOGIN_CLIENT` role is broad
  (`docs/architecture/AUTHENTICATION-BOUNDARY-REVIEW.md` §4.3, §5).
- The credential sits in the provider-owned Login V2 component, never in
  SaaS-OS.

**Requirements** for whichever mechanism is chosen:
- secure provisioning;
- secret storage per ADR-0012;
- a rotation procedure;
- least privilege (a narrower role than `IAM_LOGIN_CLIENT`, if feasible and
  verified);
- **no credential committed to Git**, and none added to `.env.example` values or
  Compose literals.

This ADR creates no credential.

**Decided (Decision 4): the system-user JWT mechanism (option 1).**

Configuration inputs, as concepts or placeholders only (no values are
recorded or created):
- `SYSTEM_USER_ID`;
- `SYSTEM_USER_PRIVATE_KEY` (or `SYSTEM_USER_PRIVATE_KEY_FILE`);
- `AUDIENCE`;
- the matching public key registered under ZITADEL `SystemAPIUsers` with
  login-client membership.

The credential must:
- be available **only** to the Login V2 component;
- use the ADR-0012 secret-management boundary;
- never be committed to Git;
- never appear as a Compose literal or in `.env.example`;
- support rotation;
- use least privilege;
- never be exposed to SaaS-OS.

Provisioning is part of the implementation phase.

## 8. Login V2 enablement (decided: per application; values not set)

| Choice | Documented behaviour |
|---|---|
| Instance-wide (`loginV2` feature `required=true`, `baseUri`) | "When the instance feature is on, it takes precedence over per-app checkboxes and applies to every application" (OFFICIALLY DOCUMENTED: `adopt-login-v2.mdx` §4). LIVE VERIFIED: the instance `baseUri` overrode the per-app base URI. |
| Per application (`loginVersion.loginV2.baseUri`, with the instance feature off) | "Only that application uses Login V2"; the gradual rollout is recommended (`adopt-login-v2.mdx` §4). |

**Values to decide before implementation:**
- **Enablement:** instance-wide or per application, and which applications,
  including the ZITADEL console.
- **Base URI:** `https://${PUBLIC_DOMAIN}/ui/v2/login` (fresh profile) or
  `https://${IDENTITY_PUBLIC_DOMAIN}/ui/v2/login` (existing profile), or the
  relative default.
- **`ZITADEL_OIDC_DEFAULTLOGINURLV2`:** default `/ui/v2/login/login?authRequest=`.
- **`ZITADEL_OIDC_DEFAULTLOGOUTURLV2`:** default
  `/ui/v2/login/logout?post_logout_redirect=`.
- **`ZITADEL_SAML_DEFAULTLOGINURLV2`:** default `/ui/v2/login/login?samlRequest=`.
- **`ZITADEL_EXTERNALDOMAIN`:** `${PUBLIC_DOMAIN}` for fresh deployments.
  It is unchanged (`${IDENTITY_PUBLIC_DOMAIN}`) for existing deployments, which
  are not moved (§1a). Changing it would require rerunning ZITADEL's setup
  phase (`self-hosting/manage/custom-domain.mdx`).
- **Forwarded-host handling:** documented as preserving `Host` or using the
  `Forwarded` host directive (`custom-domain.mdx`). For the Login container
  calling ZITADEL internally, the docs name
  `CUSTOM_REQUEST_HEADERS=Host:<public-zitadel-domain>`
  (`fork-and-deploy-login-app.mdx`).
- **Break-glass access:** the documented break-glass `IAM_OWNER` PAT before
  enablement (`adopt-login-v2.mdx`).

These defaults already point to `/ui/v2/login`, so the official path may need
no override. That must be confirmed during implementation.

**Decided (Decision 5): per-application Login V2.** Login V2 is initially
enabled for the SaaS-OS application only, not instance-wide. This
deliberately avoids changing authentication behaviour for every application,
including the ZITADEL console.

The values listed above (base URI, the three default URL settings,
forwarded-host handling, `ExternalDomain`, the break-glass `IAM_OWNER` PAT)
remain to be established in the implementation phase. None is set by this
ADR.

## 9. Cookie boundary (accepted mandatory invariant; implementation not prescribed)

**Decided (Decision 6): ACCEPTED as a mandatory security invariant.** Provider
cookies may exist on Login V2 and ZITADEL routes. Provider cookies MUST NOT be
forwarded to SaaS-OS upstreams. The exact Caddy implementation is a later
implementation decision.

```text
Browser → Login V2 / ZITADEL routes    provider cookies allowed where required
Browser → SaaS-OS upstreams            provider cookies MUST NOT be forwarded
```

On a shared host, Login V2's `sessions` cookie, which holds ZITADEL session
bearer tokens, and ZITADEL's `__Host-zitadel.useragent` cookie are host-only
with `Path=/`. They are sent by the browser to every path on
`${PUBLIC_DOMAIN}`, including SaaS-OS's backend and frontend, unless the proxy
removes them. `fingerprintId` is also set.

This was LIVE VERIFIED for the different product-origin `/login` topology
(review doc §11.4). It is **not** verified for Topology A.

The invariant applies to both profiles:
- **Fresh profile:** provider cookies share `${PUBLIC_DOMAIN}` with SaaS-OS, so
  filtering on SaaS-OS upstreams is required.
- **Existing profile:** provider cookies are host-only on
  `${IDENTITY_PUBLIC_DOMAIN}` and are not sent to `${PUBLIC_DOMAIN}`. This
  rests on the browser cookie jar in the separate-login-host spike; there was
  no SaaS-OS-side tap. It still requires verification. SaaS-OS must receive
only its own session material plus the normal OIDC callback parameters.

This ADR does not prescribe the filtering mechanism. It must be verified
against the actual production Caddy version and configuration. The cookie
names must also be re-verified for the deployed ZITADEL/Login V2 version.

**Required live verification for Topology A before acceptance of the
implementation:**
- Login V2 multi-step login;
- password + TOTP;
- passkey registration and login;
- password reset;
- provider logout;
- SaaS-OS logout;
- the SaaS-OS callback;
- SaaS-OS session persistence independent of provider cookies;
- that no provider cookie or credential material reaches either SaaS-OS
  upstream.

## 10. Deployment profiles and migration scope

**Decided (Decisions 1, 2 and 7, revised):**
- A **fresh deployment** starts directly on Topology A (the canonical
  profile). It has no identities, passkeys or sessions to carry over.
- An **existing deployment** stays on the compatibility profile (§1a):
  `${IDENTITY_PUBLIC_DOMAIN}`, its existing issuer and RP ID, with Login V2
  optionally introduced there. It is **not** migrated to `${PUBLIC_DOMAIN}`.
  Introducing Login V2 on the identity domain still needs its own rollout and
  rollback plan (§11).

A migration of an existing deployment from `IDENTITY_PUBLIC_DOMAIN` to
`PUBLIC_DOMAIN` is **deferred and out of scope** (§1a). The items below are kept
as the minimum scope such a separately approved project would have to cover:
- **Issuer:** `IDENTITY_PUBLIC_DOMAIN` → `PUBLIC_DOMAIN`, and SaaS-OS's
  `OIDC_ISSUER_URL` (§3).
- **Identity mappings:** `(issuer, subject)` (§3).
- **Passkeys and U2F:** enrolled under the old origin (§4).
- **ZITADEL hostname:** `ExternalDomain`, the ZITADEL setup-phase rerun, and
  the future of `${IDENTITY_PUBLIC_DOMAIN}` (retire it, redirect it, or keep it
  during a transition).
- **TLS certificate:** ZITADEL's internal certificate SAN, currently
  `IDENTITY_PUBLIC_DOMAIN` (`deploy/generate-identity-tls-cert.sh`).
- **Network alias:** the backend reaches ZITADEL through an alias equal to
  `IDENTITY_PUBLIC_DOMAIN` (`docker-compose.prod.yml`; enforced by
  `tests/architecture/test_production_identity_topology.py`).
- **Cookies and browser sessions:** existing provider sessions and SaaS-OS
  sessions.
- **OIDC clients:** the SaaS-OS application registration
  (`deploy/bootstrap_zitadel_production.py`) and its Login V2 enablement.
- **Redirect URIs and post-logout redirect URIs.**
- **External IdP callback URLs**, if any are configured (§6).

## 11. Rollback (strategy required before production implementation)

A rollback strategy must exist for each profile before production rollout.
For existing deployments that introduce Login V2 on the identity domain, the
issuer, identity-mapping and domain items below do not change. For fresh
deployments they apply from the start. The full list must cover:
- the issuer;
- DNS and hostnames;
- Caddy routing;
- ZITADEL `ExternalDomain`;
- Login V2 enablement (the documented rollback disables the per-app setting or
  the instance feature while Login V1 is available, using the break-glass PAT
  if interactive login is broken: `adopt-login-v2.mdx` § Roll back);
- OIDC redirect URIs;
- identity mappings;
- passkeys enrolled under either origin;
- active browser sessions.

No rollback procedure has been verified. This ADR does not invent one.

**Decided (Decision 7): ACCEPTED.** Production implementation requires an
explicit rollout, migration and rollback plan covering:
- the issuer;
- DNS and hostnames;
- ZITADEL `ExternalDomain`;
- Caddy;
- OIDC redirect URIs and post-logout URIs;
- identity mappings;
- passkeys;
- OIDC clients;
- external IdP callbacks;
- active sessions;
- TLS identity;
- network identity;
- Login V2 enablement.

The operational procedure is defined in the implementation phase, not here.

## 12. Supportability

| Level | What |
|---|---|
| **Officially documented** | ZITADEL v4.19.0 same-origin Login V2 routing (`/ui/v2/login` → Login, other paths → ZITADEL), domain reuse through the documented path-prefix list, Login V2 enablement (per app and instance-wide), the Login credential mechanisms, `ExternalDomain` as the public domain and issuer, reverse proxying with Host preservation. |
| **Live verified** | The **product-origin `/login` topology** (review doc §11): a custom build, a restricted route set, and a SaaS-OS catch-all. That topology is **not** Topology A and is not the basis for official supportability. The earlier spike also served the official artifact at `/ui/v2/login` on a product host while the issuer stayed on a separate host, which is also not Topology A. |
| **Accepted target (implemented in commit `86b63d2`; not production-verified)** | **Fresh deployments:** the Topology A configuration using the full documented route inventory (§5, Option A), which follows the documented domain-reuse model. It was live tested only in a disposable environment during implementation, not in production. Option B's restricted inventory, not selected, would **not** have been officially established. **Existing deployments:** Login V2 on ZITADEL's own domain (`${IDENTITY_PUBLIC_DOMAIN}`), which is the documented same-origin layout. It was live tested only in a disposable environment during implementation, and not with credentials enrolled under Login V1 before Login V2 was enabled. |

No partial route inventory is claimed to be officially supported.

## 13. Explicit non-goals

This decision does **not** introduce:
- embedded login;
- SaaS-OS-owned passwords;
- SaaS-OS-owned MFA;
- SaaS-OS-owned passkeys;
- authentication through the ZITADEL Management API;
- a custom authentication protocol;
- storage of provider bearer tokens in SaaS-OS;
- Topology C (`/login`);
- a custom Login V2 source build;
- any unrelated SaaS-OS identity redesign.

ADR-0026 (embedded login) remains **DRAFT — NOT ACCEPTED**.

## Options Considered

The topology alternatives (A: documented same-origin; B: documented separate
Login V2 domain; C: live-tested product-origin `/login`) are documented
without ranking in `docs/architecture/AUTHENTICATION-BOUNDARY-REVIEW.md` §12.
The human architecture owner selected Topology A. The options *within* Topology A
that were open, and are now decided under Decision, are the route inventory (§5, Option A or B), the Login V2
credential (§7), the enablement scope (§8), and the migration and rollback
approach (§10 and §11).

## Recommendation

None. This ADR did not recommend options. The choices below are the human
architecture owner's decisions.

## Decision

**Accepted by the human architecture owner (2026-09-25).**
- Topology A is the canonical production architecture for **fresh
  deployments**, and supersedes ADR-0023 §9 for them.
- **Existing deployments** retain ADR-0023 §9's identity domain (§1a).

**Decision 2 revised (2026-09-25).** After the re-review audit found passkey
and U2F preservation across an RP-ID change BLOCKED, the human architecture
owner selected **split deployment profiles** (re-review alternative 3). The
original wording, "A. Migrate before cutover: preserve existing identities and
credentials…", is superseded by the row below.

| # | Decision | Human choice |
|---|---|---|
| 1 | Deployment population | **C.** Both fresh and existing deployments, through the split profiles of Decision 2 (§1a, §10). |
| 2 | Existing identities and passkeys | **Split deployment profiles (revised).** Fresh deployments use `PUBLIC_DOMAIN`. Existing deployments keep `IDENTITY_PUBLIC_DOMAIN`. Existing credentials are preserved by keeping their RP ID. No automatic issuer or RP-ID migration is performed. Any future migration needs a separately approved project (§1a, §3, §4). |
| 3 | Route inventory | **A.** The full documented ZITADEL v4.19.0 prefix inventory. `/auth/v1/*` is reserved for ZITADEL; `/auth/login`, `/auth/callback`, `/auth/logout` and `/auth/me` belong to SaaS-OS; downstream products inherit the reservation (§5). |
| 4 | Login V2 credential | **A.** A system-user JWT (`SYSTEM_USER_ID`, `SYSTEM_USER_PRIVATE_KEY`, `AUDIENCE`), Login V2-only, under the ADR-0012 boundary, rotatable, least privilege, never in Git, Compose literals, `.env.example` or SaaS-OS (§7). |
| 5 | Login V2 enablement | **B.** Per application: the SaaS-OS application first, not instance-wide (§8). |
| 6 | Cookie boundary | **ACCEPTED** as a mandatory invariant. The implementation is to be decided later and live-tested (§9). |
| 7 | Rollout and rollback | **ACCEPTED.** An explicit rollout, migration and rollback plan is required before production (§10, §11). |

**What acceptance authorizes:** implementation *planning* and a separate
implementation phase against this architecture.

**What it does not authorize:**
- immediate production rollout;
- any migration of an existing deployment from `IDENTITY_PUBLIC_DOMAIN` to
  `PUBLIC_DOMAIN` (deferred, and separately approved if ever wanted: §1a);
- production acceptance before the §9 live verification and the §11 plan
  exist.

The architecture described by this ADR has been implemented for the fresh
and existing deployment profiles described above (commit `86b63d2`). No
existing deployment has been migrated, no automatic issuer, RP-ID, passkey or
U2F migration is implemented or implied, and no production rollout has been
performed.

## What Would Be Difficult to Change Later

- **The issuer.** Every `(issuer, subject)` mapping and every token validation
  depends on it. Changing it again repeats the §3 migration.
- **The passkey origin.** Passkeys enrolled under `${PUBLIC_DOMAIN}` (fresh)
  or `${IDENTITY_PUBLIC_DOMAIN}` (existing) are bound to that RP ID. Any later
  move of the Login V2 host would break them, which is why existing
  deployments keep their domain.
- **Two deployment profiles.** Fresh and existing deployments differ in
  domain, issuer and RP ID. Deployment artifacts, tests and documentation must
  support both until any separately approved migration exists.
- **The reserved URL namespace.** Once ZITADEL's prefixes are served on the
  product domain, products cannot use them, and future ZITADEL releases may add
  more.
- **The Login V2 credential.** A service credential with login-client authority
  becomes a long-lived, high-value secret.

## Related

- ADR-0005: identity build vs buy. Unchanged; this ADR preserves its boundary.
- ADR-0023: §9's separate identity subdomain is superseded by this ADR **for
  fresh deployments only**. It remains the architecture for existing
  deployments, now with Login V2 optionally on that domain.
  §5 (identity mapping) and the issuer-migration note are relied on here.
  ADR-0023 is unchanged by this ADR.
- ADR-0026 (embedded login; formerly numbered ADR-0024): DRAFT — NOT ACCEPTED; unaffected.
- ADR-0012 (secrets), ADR-0015 and ADR-0017 (downstream products inherit the
  reserved namespace).
- `docs/architecture/AUTHENTICATION-BOUNDARY-REVIEW.md` §10 to §12: the
  investigation, live verification, supportability evidence and topology
  alternatives.
- Implementation (commit `86b63d2`): `deploy/caddy/identity-profile-fresh.caddyfile`,
  `deploy/caddy/identity-profile-existing.caddyfile`,
  `deploy/check-identity-profile.sh`, `deploy/generate-login-client-key.sh`,
  `deploy/zitadel-login-client-system-user.yaml`,
  `tests/architecture/test_identity_profile_guard.py`,
  `tests/architecture/test_identity_proxy_routing.py`.
- Current topology artifacts: `Caddyfile`, `docker-compose.prod.yml`,
  `deploy/bootstrap_zitadel_production.py`,
  `deploy/generate-identity-tls-cert.sh`,
  `tests/architecture/test_production_identity_topology.py`,
  `scripts/check-docker-prod.sh`.
