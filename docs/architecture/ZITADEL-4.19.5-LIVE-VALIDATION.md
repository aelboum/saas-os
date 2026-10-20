# ZITADEL v4.19.5: disposable-stack live validation (2026-10-20)

**Status: evidence record.** This page records what was observed when the
merged ZITADEL v4.19.5 configuration (pull request #76, merge commit
`73dd9c6`) was run against a disposable, non-production stack. It does not
claim that any real deployment is upgraded or secure, and it does not claim
complete live validation: three items remain unverified (section 4).

## 1. Method

- **Tree:** `main` at `73dd9c6b5f02791b3e4c8c4eb976b5d5d5e98556`, clean.
- **Stack:** `SAAS_OS_TIER2_KEEP=1 scripts/check-docker-prod-tls.sh`
  (ADR-0027), Compose project `saas-os-tier2-8774`, `IDENTITY_PROFILE=fresh`
  on `app.localhost`. The harness itself passed ("Tier 2 production
  validation PASSED", exit 0), then the stack was kept for the tests below.
- **Images:** `ghcr.io/zitadel/zitadel:v4.19.5`,
  `ghcr.io/zitadel/zitadel-login:v4.19.5`, and the SaaS OS images built from
  that tree.
- **Credentials:** all disposable and generated for the run (master key,
  database and Redis passwords, first-admin password, bootstrap token,
  login-client key, Login V2 cookie secret, TLS CA). No value was printed or
  kept; all were deleted with the stack.
- **Probes:** `curl` in a container on the project's own networks, verifying
  TLS against the run's Caddy CA or ZITADEL's identity CA (never
  `--insecure`); ZITADEL API calls from a one-off container of the project's
  `zitadel-bootstrap` image. No browser was used.
- **Isolation:** no existing ZITADEL instance, Docker project, volume or
  network was touched. Host ports 80 and 443 were free before the run.

## 2. Results

| # | Test | Result | Evidence |
|---|---|---|---|
| 1 | Login V2 sign-in through its pages in a browser, `fresh` profile | **NOT RUN** | No browser automation was authorized for this run |
| 1b | Same, `existing` profile | **NOT RUN** | The harness sets `IDENTITY_PROFILE=fresh` only |
| 2 | Login V2 `sessions` cookie signing | **PASS** | Cookie entries for a real ZITADEL session were built with the v4.19.5 algorithm (HKDF-SHA256 of the secret, info `zitadel-login-session-cookie-v1`, HMAC-SHA256 over `["v1", sorted fields]`) and sent to `/ui/v2/login/accounts`. Correctly signed: the account is listed. Changed signature, unsigned (the pre-v4.19.2 format), or a changed field under the old signature: not listed, and Login V2 logs "ignoring 1 session cookie entries with a missing or invalid signature". No cookie: not listed |
| 3 | Host and identity headers | **PASS, partial** | Through Caddy, client-supplied `X-Zitadel-Instance-Host`, `X-Zitadel-Public-Host`, `X-Zitadel-Forward-Host` or `X-Forwarded-Host` set to `evil.example` leave the discovery issuer at `https://app.localhost` (200). The same headers sent to ZITADEL directly, bypassing Caddy, return 404 `QUERY-1kIjX` "Instance not found", so the headers matter and the edge neutralizes them. `Host: evil.example` sent directly to ZITADEL: 404 `QUERY-1kIjX`; through Caddy: an empty 200 from Caddy, never forwarded. Not shown here: per-cookie stripping on SaaS OS routes (section 4) |
| 4 | Bootstrap with more than 100 projects | **PASS** | With 150 dummy projects, `ListProjects` without a limit returned 100 of 152 (`appliedLimit` 100): the truncation the pagination fix addresses. With the `saas-os` project deleted, bootstrap run 1 created it at list position 151 (page 2); run 2 reported "already exists" with the same client ID. One `saas-os` project at the end |
| 5 | Bootstrap with more than 100 applications | **PASS** | With 150 dummy applications and `saas-os-backend` deleted, run 3 created it at position 150; run 4 found it with the same client ID. One `saas-os-backend` at the end |
| 6 | List limits | **PASS** | `limit` 1001: 400 `Limit exceeded (QUERY-4M0fs)`; no limit: `appliedLimit` 100. Empty pages short of the total and the page bound are covered only by the unit tests |
| 7 | OIDC sign-in and the SaaS OS callback | **PASS, Login V2 pages bypassed** | `/auth/login` 303 to `/oauth/v2/authorize` (code, PKCE S256); authorize 302 to `/ui/v2/login/login`. The Login V2 step was performed through ZITADEL's API as Login V2 does it (Session API with a password check, then `CreateCallback` with the login client's system-user JWT). `/auth/callback` 303 to `/` and set `saas_os_session`; `/auth/me` 200; replaying the same callback 400 |
| 8 | Invalid Login V2 secret | **PASS** | Unset or empty is refused by Compose (CI test). A 16-character value, alone or anywhere in a comma-separated list: "ZITADEL_SESSION_COOKIE_SECRET is invalid: every value must be at least 32 characters long", `/ui/v2/login/ready` 503, the image's own healthcheck turns the container unhealthy after about 65 seconds, and signed cookies are no longer accepted. `new,<original>`: ready, and cookies signed with the original are still accepted (rotation). Restored to the original configuration (same Compose config hash) |
| 9 | Secrets in logs | **PASS** | Ten disposable secrets (master key; ZITADEL, application and admin database passwords; Redis password; first-admin password; cookie secret; bootstrap token; login-client private key; a session token) searched for in the logs of all 15 project containers: no match. The same search finds an expected value (the client ID) in the bootstrap log |
| 10 | Restart and recovery | **PASS** | During `docker compose restart zitadel zitadel-login`: discovery 502 while an existing SaaS OS session kept working (`/auth/me` 200). Afterwards: both healthy, discovery 200, `/ready` 200, the signed Login V2 cookie still accepted, a new `/auth/login` 303 |

For test 7 the disposable `backend` was recreated with `OIDC_ISSUER_URL`,
`OIDC_CLIENT_ID`, an empty `OIDC_REDIRECT_URI` and `AUTH_COOKIE_SECURE=true`.
The harness otherwise passes the developer's local `.env` to `backend`, whose
local-development redirect URI disagrees with the stack's
`PUBLIC_APP_ORIGIN`; the backend correctly refused to start a login
(`auth_not_configured`, 503) until that was overridden.

## 3. Findings

| Finding | Severity | Disposition |
|---|---|---|
| With an invalid Login V2 secret, `/ui/v2/login` still serves pages (200) while `/ready` is 503; `proxy` waits for `zitadel-login` only with `service_started`, so a deployment with a bad secret comes up and logins fail | LOW (fails closed: nothing can be signed) | Open; ledger |
| The TLS harness passes the operator's `.env` to `backend` without overriding the OIDC settings, so its stack cannot complete a login | LOW (test infrastructure) | Open; ledger |
| The TLS harness never removes the images it builds (`saas-os-tier2-<pid>-*`) | LOW (test infrastructure) | Open; ledger |
| The TLS harness covers the `fresh` identity profile only | LOW (test coverage) | Open; ledger |

## 4. Not verified

- Signing in through the Login V2 pages in a real browser, on either profile.
- The `existing` identity profile.
- The 88 Caddy routing tests in `tests/architecture/test_identity_proxy_routing.py`
  (per-cookie stripping and header handling on every route); they need a
  Caddy v2.11.4 binary and are skipped locally and in CI.
- `tests/core/identity/test_live_zitadel_integration.py` (opt-in,
  `ZITADEL_LIVE_TEST=1`); test 7 exercised more of the flow.
- A real domain, CDN or reverse proxy, multiple Login V2 replicas, and any
  product's running deployment.

## 5. Cleanup

`docker compose -p saas-os-tier2-8774 down -v --remove-orphans`, then that
project's four built images, the harness's temporary directory (CA, keys,
override) and every generated credential file were removed. Verified by
Compose label and by name: no container, volume, network or image of the
project remained. Other local stacks were not changed.
