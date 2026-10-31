# Changelog

SaaS OS releases (ADR-0015, "Release labels" and "One pull request per release"). Each entry names the exact commit; the newest names its release pull request until the next release writes in the SHA. Consumers pin that SHA, never the tag (`docs/CONSUMER-GUIDE.md` section 3). Upgrade steps are in `docs/CONSUMER-GUIDE.md` section 14. Each entry is also the body of the release's GitHub Release, which the Release workflow creates for the tag (`docs/RELEASING.md`); a GitHub Release is not a package publication.

## v0.6.0 (2026-10-31)

The merge commit of pull request #185, the release pull request (ADR-0015, "One pull request per release"). The next release writes its full SHA here. Until then, check that the tag `v0.6.0` resolves to that merge commit before pinning it. From this release on the tag is signed with the owner's key; check it with `git tag -v v0.6.0` (ADR-0015 amendment of 2026-10-31).

It contains everything since v0.5.0 (`b03d87a`): pull requests #102 to #132 and #134 to #184, and this release (#133, release 2 of retiring `http://` webhook destinations, is not in it). A minor release, not a patch: it has a migration, new settings, new required deployment steps and changed public signatures (ADR-0015, version numbers before 1.0).

**Deployment steps (do these before or while upgrading; details in `docs/CONSUMER-GUIDE.md` section 14, "From v0.5.0 to v0.6.0"):**

- **Migration** `b3d5f7a9c2e4` (#179): it widens the platform-permission check to twenty-four values. Run `saas-os-migrate upgrade head` with the migration role. Its downgrade refuses while a grant of the new permission exists.
- **ZITADEL master key from a file** (#153, ADR-0012 amendment of 2026-10-29). `docker-compose.prod.yml` starts ZITADEL with `--masterkeyFile`; `.env` must set `ZITADEL_MASTERKEY_FILE` to a file holding exactly the 32-byte key, with no trailing newline, readable by uid 1000. Compose refuses to start without it. Move an existing deployment with the same key: `docs/RUNBOOKS.md`, "Self-hosted identity operations", section 5a.
- **Worker egress through a proxy** (#127 to #129, #132, ADR-0059). In the reference topology the worker joins internal networks only and reaches the Internet through `egress-proxy` (Squid, `CONNECT` to IP literals on port 443 only) and `dns-resolver` (Unbound). Webhook delivery and Resend use `EGRESS_PROXY_URL`. An SMTP relay must be reachable on `internal` (ledger row G9).
- **Stripe SDK checked at start** (#159). With `STRIPE_API_KEY` set and no `saas-os[stripe]` installed, the API and the worker refuse to start, instead of failing at the first billing call.
- **Images without package managers** (#161, #162). Both images pin their base by digest, drop `pip` (backend) and `npm` (frontend) at runtime, and are scanned with an SBOM in CI. Do not `pip install` or `npm install` inside a running container; build a new image.
- **Owners bootstrapped before this release** (#179). `platform.outbox:replay` is new; the first owner of a new installation holds it, an existing owner does not. Grant it with `python -m saas_os.api.platform_bootstrap recover ... --grant platform.outbox:replay` (`docs/RUNBOOKS.md`, "Platform operators").

**New settings:** `EMAIL_PROVIDER=resend` with `RESEND_API_KEY` (#102, ADR-0058), `EGRESS_PROXY_URL` (#128), `WEBHOOK_ALLOW_HTTP` (#131: unset allows `http://` with a deprecation log line; `false` refuses it; `true` allows it silently), `API_KEY_MAX_PER_USER` (#177, default 50, 1 to 100000), `OUTBOX_RETRY_HINT_MAX_SECONDS` (#178, default 86400, at most 31 days), `ZITADEL_MASTERKEY_FILE` (#153).

**Behaviour a product sees:**

- **API keys per user are limited** (#177). `create_api_key` refuses an unrevoked key beyond `API_KEY_MAX_PER_USER`, counted across all tenants, with `ApiKeyLimitExceededError`; the route answers `409` "The API key limit has been reached.". A revoked key cannot be rotated (#112).
- **A malformed `ai.tokens` entitlement refuses** (#176). The AI request fails with `InferenceQuotaExceededError("quota_invalid")` before the ledger is read, also with `AI_INFERENCE_TOKEN_QUOTA_REQUIRED` off.
- **A move under a suspended parent is refused** (#175). `move_tenant` raises `TenantParentRuleError` with reason `parent_suspended`, and writes a `denied` row.
- **Outbox retry hints and replay** (#178, #179). A consumer may raise `RetryAfterEventError(seconds, reason)`; the next attempt waits at least that long, within `OUTBOX_RETRY_HINT_MAX_SECONDS`, and still counts. Resend reads `Retry-After` on a `429` and waits up to the bound on a quota refusal (`NotificationDeferredDispatchError`). `saas-os-operator replay-outbox-events` returns one tenant's dead-lettered events (at most 1000) to `pending`, under `platform.outbox:replay`, with platform and tenant audit rows; it only counts unless `--apply` is given.
- **Paged lists** (#172). `list_tenant_members`, `list_invitations_for_tenant` and `list_api_keys` take optional keyword-only `limit` and `offset` (and `user_id` for API keys) and page in SQL. Additive: without them they return everything, as before.
- **Stored strings refuse control characters** (#149, #151). Each module refuses NUL and other control characters in the strings it stores with its own validation error; an outbox claim is given back when the queue's refusal quotes a NUL byte.
- **Errors and logs carry less** (#108 to #110, #122, #126, #135 to #139, #144, #173). Webhook URLs, OIDC issuer, subject and email, httpx request lines, uvicorn access paths and job arguments are kept out of errors, stored error fields and logs; stored webhook URL errors are redacted; identity discovery requires a matching issuer and an `https` `jwks_uri`; identity and GitHub clients use an explicit proxy and trust store and follow no redirects. An invitation email that cannot be stored is refused.
- **Contract catalogs** (#182). A Product Contract may declare the Core modules `outbox` and `email` and the Infrastructure service `egress`.
- **Self-learning** (#113, #156, #174). Only a recorded proposal can be withdrawn; production-effect transitions are audited in their own transaction; the Policy Gate's inputs and `create_canary`'s rows are verified.
- **Frontend dependencies** (#103, #107): `undici` 8.12.3 and `vitest` 5.0.3 for their advisories.

**Repository and release tooling:**

- CI and the backend image install exact versions from `constraints.txt` (#181, ADR-0041 amendment); `pyproject.toml` keeps lower bounds. Every action in `ci.yml` is pinned to a commit SHA (#121). The TLS production validation and the single-origin runtime check run in the required Docker job (#164, #165, #167). The public import surface is pinned in a reviewed snapshot (#170), and living documents fail CI on a missing path or ADR number (#171).
- Release tags from v0.6.0 on must be signed with the owner's key and verified by GitHub before the Release workflow publishes them (#184, ADR-0015 amendment of 2026-10-31).
- Staging deployment of the reference stack is prepared, not run (#183, `docs/STAGING.md`).
- Documentation, decision briefs and production-readiness records (#104 to #106, #111, #120, #123 to #125, #130, #134, #140 to #143, #145 to #148, #150, #152, #154, #155, #163, #166), and fixes to tests and local tooling (#114 to #119, #157, #158, #160, #168, #169, #180).

The example pins move to v0.5.0 (`b03d87a`), the previous release, as ADR-0015 requires (`docs/P-ROADMAP.md`, "Example pins moved to `b03d87a` (v0.5.0)"); the examples' use of `register_purge_participant()` now installs from their pin. Migration head: `b3d5f7a9c2e4` (was `f6a2c8e4b1d9`). Production readiness stays NO-GO (`docs/PRODUCTION-READINESS.md`). Before upgrading, read `docs/CONSUMER-GUIDE.md` section 14, "From v0.5.0 to v0.6.0".

## v0.5.0 (2026-10-23)

Commit `b03d87a5272924d1e413c144dc5c3b41ac430580`, the merge commit of pull request #101, the release pull request (ADR-0015, "One pull request per release"). Main CI run 40002133371 passed on this commit. Check that the tag `v0.5.0` resolves to that SHA before pinning it.

It contains everything since v0.4.1 (`a313c59`): pull requests #94, #96, #98, #99 and #100 and this release. A minor release, not a patch, because it adds public API and tightens tenant-purge participant registration (ADR-0015, version numbers before 1.0). There is no migration and no new deployment step.

- **Public tenant-purge participant API** (#94). `saas_os.core.tenancy` exports `TenantPurgeParticipant`, `register_purge_participant()`, `registered_purge_participant_names()`, `DuplicateTenantPurgeParticipantError` and `InvalidTenantPurgeParticipantError`. These are the supported way for a product to register its purge participants (`docs/CONSUMER-GUIDE.md` section 11). `saas_os.core.tenancy.purge_participants` still imports.
- **Registration is checked** (#94). A participant must have a `name` and a callable `purge_tenant_data(tenant_id)`. The name must match `[a-z0-9][a-z0-9._-]{0,99}` (lowercase letters, digits, `.`, `_` and `-`). Anything else raises `InvalidTenantPurgeParticipantError`, a `ValueError`, and nothing is registered. Registering the same object again is now a no-op; a different object under a registered name still raises `DuplicateTenantPurgeParticipantError`.
- **Participant failures are always `participant_error`** (#94). A participant that raises one of Core's own exception types is recorded in `tenant.purge_failed` as `participant_error`, not as a Core failure class.
- **Operator command** (#94). `saas-os-operator purge-tenant --setup my_product.purge:register_purge_participants` works with a setup function that does not build the application. Before, every audit write in that fresh process failed with `NoReferencedTableError`.
- **`--no-product-participants` is audited** (#99). `purge_tenant()` takes a keyword-only `product_participants_skipped: bool = False`; the operator command passes `True` for `--no-product-participants`, and `tenant.purge_completed` then records `product_participants_skipped: true`. Other purges record the same metadata as before. Participants registered in the process still run, so the key can appear with `participants_run` above 0. Its absence does not prove that every participant a product needs was registered.
- **`AuthorityNotAuthorizedError` is public** (#98). `from saas_os.core.rbac import AuthorityNotAuthorizedError`. It is the same class as before (`PermissionError`, attributes `operation` and `tenant_id`) and still does not say why a caller was refused (ADR-0031).
- **The `braces` exception is closed** (#100). GitHub withdrew GHSA-vfj7-8cjw-p6xm, so `npm audit` no longer reports it and the security gate failed on its now-stale exception, as designed. The entry is removed from `scripts/security-exceptions.json`, which now holds no exception; the gate's code and threshold are unchanged, and no dependency or lockfile changed (`braces` is still 3.0.3). `docs/SECURITY-EXCEPTION-braces.md` records the closure. If the advisory is reported again, the gate fails.
- **Purge entry points and G1** (#96). `docs/P-ROADMAP.md` records the owner's decision that the operator command and a direct `purge_tenant()` call are the supported purge entry points, and reopens the purge-participant acceptance gate G1.

The example pins move to v0.4.1 (`a313c59`), the previous release, as ADR-0015 requires (`docs/P-ROADMAP.md`, "Example pins moved to `a313c59` (v0.4.1)"). Migration head: `f6a2c8e4b1d9`, unchanged. Before upgrading, read `docs/CONSUMER-GUIDE.md` section 14, "From v0.4.1 to v0.5.0".

## v0.4.1 (2026-10-22)

Commit `a313c591c680e0fde0cdfc64c0e92b6cacc1bde4`, the merge commit of pull request #93, the release pull request (ADR-0015, "One pull request per release"). Main CI run 39854310194 passed on this commit. Check that the tag `v0.4.1` resolves to that SHA before pinning it.

It contains everything since v0.4.0 (`77c9a22`): pull requests #91 and #92 and this release. A patch release: a security fix in the frontend's dependencies and a release-tooling fix. There is no migration, no changed public signature and no new deployment step.

- **Next.js 15.5.28** (#92). The frontend moves from `next` 15.5.27 to 15.5.28 (`"next": "^15.5.28"`; the lockfile changes only `next`, `@next/env` and the `@next/swc-*` binaries). 15.5.27 is affected by GHSA-2464-fhr4-w9xw (critical: unauthenticated remote code execution in the Image Optimization API when SVG files are used) and GHSA-p3m5-59mp-jv5r (high: denial of service in the App Router using Server Actions); 15.5.28 is the first patched 15.x release for both. A product that builds the SaaS OS frontend from v0.4.0 or earlier should rebuild from this release.
- **Release validation waits for GitHub's lists** (#91). `scripts/release.py` asks again, at most 6 times 5 seconds apart, when GitHub's list answers are still empty: no CI run for the commit, or, at `verify`, no release for the tag. A run or release that is found is judged as before, and API errors still fail. v0.4.0's Release run failed its own verification this way although the release was correct (`docs/RELEASING.md`).

The example pins move to v0.4.0 (`77c9a22`), the previous release, as ADR-0015 requires (`docs/P-ROADMAP.md`, "Example pins moved to `77c9a22` (v0.4.0)"). Migration head: `f6a2c8e4b1d9`, unchanged. Before upgrading, read `docs/CONSUMER-GUIDE.md` section 14, "From v0.4.0 to v0.4.1".

## v0.4.0 (2026-10-22)

Commit `77c9a22b3ab878dfa95293ff4e9bbf00d5e05517`, the merge commit of pull request #90, the release pull request (ADR-0015, "One pull request per release"). Main CI run 39811217732 passed on this commit. Check that the tag `v0.4.0` resolves to that SHA before pinning it.

It contains everything since v0.3.0 (`5905156`): pull request #89 and this release. A minor release, not a patch, because of one new required deployment step for some deployments: a production deployment that sends email over plaintext SMTP (`SMTP_USE_TLS=false`) must now enable TLS, or set `SMTP_REQUIRE_TLS=false` to keep a deliberately plaintext relay (ADR-0015, version numbers before 1.0). There is no migration and no changed public signature (additions only).

- **Deployment-level email provider selection** (#89, ADR-0057). `EMAIL_PROVIDER` names one entry of a fixed, built-in map: `smtp`, or `mailpit`, which is refused unless `ENVIRONMENT` is `development` or `test`. Unset, it selects `smtp`, as before. A product that passes `provider=` to `send_email()` is unaffected. When `EMAIL_PROVIDER` is set, the worker checks the email configuration and `EMAIL_DEFAULT_SENDER` at startup and refuses to start if either is wrong.
- **SMTP TLS** (#89). `SMTP_TLS_MODE` is `starttls`, `implicit` (new) or `none`. `SMTP_USE_TLS` remains as an alias; a setting that contradicts `SMTP_TLS_MODE` is refused. With `ENVIRONMENT=production`, TLS is required unless `SMTP_REQUIRE_TLS=false`. Server certificates are always verified; no setting turns that off.
- **Notification email failures and Message-ID** (#89). A permanent SMTP refusal (5xx for the sender, the data, or every recipient) dead-letters the notification's outbox event after one attempt; every other failure keeps the existing retry policy. Every message carries a `Message-ID`, and a notification's is derived from its outbox event id, so a resend after a crash repeats it and a receiver can deduplicate on it. Delivery is still at-least-once, not exactly-once. The send runs in a worker thread (`asyncio.to_thread`) instead of on the event loop. Logs carry the provider, the duration, a permanent flag and the numeric reply code, never addresses, subjects, bodies, credentials or the server's reply text.
- **Mailpit for development** (#89). `docker-compose.yml` adds a `mailpit` service (`axllent/mailpit:v1.31.3`): SMTP only on the Compose network, web UI on `127.0.0.1:8025`. It is not in `docker-compose.prod.yml`.
- **Verification** (#89). Besides CI, a live run on a disposable, isolated stack sent a notification through `dispatch_notification()`, the outbox, the worker and the Mailpit adapter and read it back through Mailpit's API: the completion fence, a retry carrying the same Message-ID, and real 550 and 451 refusals behaved as described above. A real external SMTP relay was not tested.

The example pins move to v0.3.0 (`5905156`), the previous release, as ADR-0015 requires (`docs/P-ROADMAP.md`, "Example pins moved to `5905156` (v0.3.0)"). Migration head: `f6a2c8e4b1d9`, unchanged. Still open: in the reference production topology the worker has no route to the Internet, so a deployment must provide the outbound connectivity its SMTP relay needs (G9, `docs/P-ROADMAP.md`). Before upgrading, read `docs/CONSUMER-GUIDE.md` section 14, "From v0.3.0 to v0.4.0".

## v0.3.0 (2026-10-21)

Commit `5905156a99a4526e5071ce091a58667c08b0a019`, the merge commit of pull request #86, the release pull request (ADR-0015, "One pull request per release"). Main CI run 39628783399 passed on this commit. Check that the tag `v0.3.0` resolves to that SHA before pinning it.

It contains everything since v0.2.0 (`8e053be`): pull requests #80 to #85 and this release. A minor release, not a patch, because of one new required deployment step: the production Compose file needs a second configuration file, `.env.app` (ADR-0015, version numbers before 1.0). There is no migration and no changed public signature.

- **Identity secrets stay out of the application containers** (#82, ADR-0012 amendment of 2026-10-21). `docker-compose.prod.yml` loads the new `.env.app` into `backend` and `worker` only; `frontend` and `proxy` load no file, and `.env` is used only for Compose's own `${...}` substitution. Before, `.env`, with `ZITADEL_MASTERKEY` and the other identity secrets, was loaded whole into all four services. Compose refuses to run without `.env.app`. The host timers in `deploy/` read `.env.app`; the ZITADEL backup timer reads both files. Template: `.env.app.example`. Steps: `docs/RUNBOOKS.md`, "Production configuration files".
- **certifi floor raised to 2026.10.19** (#81, PYSEC-2026-4320). The strict egress client builds its TLS context from certifi's bundle.
- **The proxy waits for a ready Login V2** (#81). `zitadel-login` has a healthcheck on `/ui/v2/login/ready`, and `proxy` starts only once it passes.
- **Production checks** (#81, #82). `scripts/check-docker-prod.sh` removes only its own Compose project. `scripts/check-docker-prod-tls.sh` runs the `fresh` and `existing` identity profiles, removes the images it built, and fails if any `ZITADEL_` variable reaches `backend`, `worker`, `frontend` or `proxy`.
- **CI runs the Caddy routing tests** (#83). Caddy v2.11.4 is installed by checksum and the proxy routing suite is required, not skipped.
- **Publication waits for approval** (#85, ADR-0015 amendment of 2026-10-21). The Release workflow's `publish` job runs in the `release` environment, which requires the owner's approval and accepts only `v*` tags.
- **Documentation** (#80, #84): the Release workflow's first publication (v0.2.0); the Phase 9 re-certification against its recovered specification (re-certified with findings, `docs/architecture/PHASE-9-RECERTIFICATION.md`), with structural tests; the `braces` security exception re-checked.

The example pins move to v0.2.0 (`8e053be`), the previous release, as ADR-0015 requires (`docs/P-ROADMAP.md`, "Example pins moved to `8e053be` (v0.2.0)"). Migration head: `f6a2c8e4b1d9`, unchanged. Before upgrading, read `docs/CONSUMER-GUIDE.md` section 14, "From v0.2.0 to v0.3.0".

## v0.2.0 (2026-10-21)

Commit `8e053be4ba88a504193d627269effefcf7af49bc`, the merge commit of pull request #79, the release pull request (ADR-0015, "One pull request per release"). Main CI run 39555344527 passed on this commit. Check that the tag `v0.2.0` resolves to that SHA before pinning it.

It contains everything since v0.1.2 (`b0809ee`): pull requests #72 to #78 and this release. A minor release, not a patch, because of one new required deployment value (ADR-0015, version numbers before 1.0). There is no migration and no changed public signature.

- **ZITADEL v4.19.5, with a required Login V2 session-cookie secret** (#76). `zitadel` and `zitadel-login` move from v4.19.0 to v4.19.5 in both Compose files. This fixes the unsigned Login V2 session cookie (GHSA-jh92-5mrj-p2w2, High: account takeover by guessing a session ID) and SAML identity-provider confusion (GHSA-x4c7-fpcx-w9q6, High, only where a SAML identity provider is configured). `docker-compose.prod.yml` now refuses to start without `ZITADEL_SESSION_COOKIE_SECRET`: at least 32 characters, the same on every `zitadel-login` replica, comma-separated for rotation (`docs/RUNBOOKS.md`, "Self-hosted identity operations", section 11).
- **Identity bootstrap: complete listings** (#76). `saas-os-local-identity` reads projects and applications page by page. ZITADEL v4.19.5 returns at most 100 rows per list call by default, so a bootstrap against an instance with more than 100 projects could miss the existing `saas-os` project and create a duplicate. A listing that ends early or reaches the page bound now stops the bootstrap with `IncompleteListingError` instead of acting on a partial list.
- **Live validation of v4.19.5** (#77, `docs/architecture/ZITADEL-4.19.5-LIVE-VALIDATION.md`). On a disposable TLS stack: cookie signing and tamper rejection, pagination past 100 projects and 100 applications, the OIDC code flow, secret rotation and refusal of an invalid secret, and no secret in any log. Browser sign-in through the Login V2 pages, the `existing` identity profile and the Caddy routing tests were not run.
- **Frontend development dependency** (#78). vite 8.2.2 to 8.3.4 (GHSA-587h-7wmj-h5pm, development server only; `npm audit --omit=dev` was already clean).
- **Release automation** (#72 to #74, ADR-0015 amendment "GitHub Releases"). `scripts/release.py` and `.github/workflows/release.yml` validate a tag and create its GitHub Release from this file. This is the first release published by the workflow.
- **Documentation** (#75): the `main` branch ruleset.

The example pins move to v0.1.2 (`b0809ee`), the previous release, as ADR-0015 requires (`docs/P-ROADMAP.md`, "Example pins moved to `b0809ee` (v0.1.2)"). Migration head: `f6a2c8e4b1d9`, unchanged. Before upgrading, read `docs/CONSUMER-GUIDE.md` section 14, "From v0.1.2 to v0.2.0".

## v0.1.2 (2026-10-20)

Commit `b0809eeb3448956a4dc85a5541514823ec9ceae7`, the merge commit of pull request #71, the release pull request (ADR-0015, "One pull request per release"). Main CI run 39392316234 passed on this commit. Check that the tag `v0.1.2` resolves to that SHA before pinning it.

It contains everything since v0.1.1 (`c7d8987`): pull requests #66 to #70 and this release. A fix release: no migration, no changed public signature, one new optional setting.

- **Webhook delivery: one deadline per attempt** (#70, ADR-0035 amendment of 2026-10-19). Resolution, every address tried, the request and the response status share one 10-second deadline. Before, 10 seconds applied to each phase. An expired deadline is `WebhookDeliveryError("deadline_expired")`, retried by the outbox like any other transient failure.
- **Webhook delivery: DNS off the event loop** (#70). Resolution runs in a worker thread, so a slow resolver no longer stalls the other jobs on the worker.
- **Webhook delivery: address fallback** (#70). When connecting to the first validated address fails before anything was sent, the second is tried; at most two per attempt. Every resolved address must still be public.
- **Webhook delivery: optional port allowlist** (#70). `WEBHOOK_ALLOWED_PORTS`, a comma-separated list. Unset, any port stays allowed, so nothing changes by default. Set, it is checked when a subscription is created and before every delivery.
- **Tests and documentation** (#66 to #69): payment-page audit failure tests, the ADR-0015 amendment "One pull request per release", the example pins moved to v0.1.1, and status lines in `docs/AI-CONTROL-PLANE.md` and `docs/RELEASE-READINESS.md`.

The example pins stay at v0.1.1 (`c7d8987`), the previous release, as ADR-0015 requires. Migration head: `f6a2c8e4b1d9`, unchanged. Before upgrading, read `docs/CONSUMER-GUIDE.md` section 14, "From v0.1.1 to v0.1.2".

## v0.1.1 (2026-10-19)

Commit `c7d898782877b945a54d49c87d280c6ad515586f`, `main` after pull request #65 (the release pull request; its SHA is recorded by the pin-move pull request, ADR-0015 "Release labels", order). Check that the tag `v0.1.1` resolves to that SHA before moving a pin.

It contains everything since v0.1.0 (`dab6357`): pull requests #62 to #64 and this release. A fix release: no migration, no changed public signature, no new deployment step.

- **AI inference: an exhausted OpenAI-compatible account is no longer a rate limit** (#64). A 429 whose `error.code` is `insufficient_quota` is the new error category `provider_quota_exhausted`: not retried on the same destination, may fall back, and the caller gets `InferenceProviderUnavailableError("provider_quota_exhausted")`. Only `error.code` is compared. Alerts or reports that count `rate_limited` attempts no longer include these.
- **AI inference: trust entries are re-checked before every attempt** (#64). A trust entry revoked, expired or added while a request runs refuses its next attempt with `destination_changed`.
- **Tests** (#63): service-level tests for the deadline between retries, `Retry-After` beyond the deadline and destination changes.
- **Release labels** (#62): this file, the ADR-0015 amendment and `docs/CONSUMER-GUIDE.md` sections 14 and 15; the example pins moved to v0.1.0.

Migration head: `f6a2c8e4b1d9`, unchanged. Before upgrading, read `docs/CONSUMER-GUIDE.md` section 14, "From v0.1.0 to v0.1.1".

## v0.1.0 (2026-10-19)

Commit `dab6357e4eefc19ab7308cf553e38f658ddd08d0`, `main` after pull request #61. The first tagged release. Main CI run 39251055117 passed on this commit.

It contains everything up to and including pull request #61. Since `4197d2f` (pull request #43, the previous pin of the example consumers):

- **Audit digests** (#52, ADR-0053): the worker writes one `audit_digest` line per settled window of the audit tables to its log, for an append-only external store; `python -m saas_os.ops.audit_digest verify`. Migration `d3e9a1c47b20`.
- **Payment-page audit** (#51, ADR-0052 amendment): `billing.payment_page_issued`, `billing.payment_page_issued_for_account` and `billing.payment_page_refused`.
- **Governed AI inference v1** (#53 to #58, ADR-0054 to ADR-0056; #55 and #57 moved the reference consumer's pin): `saas_os.inference.run_inference` with OpenAI-compatible, Anthropic and Gemini adapters, Redis admission, a soft token quota, cost estimates, the attempt ledger, the `saas-os-operator ai-*` commands and the platform-configuration database role. Migrations `a7f3c91e2d48`, `e4b8c2d6f1a3`, `b8e2d4f6a1c3`, `c5d7e9f1a2b4` and `f6a2c8e4b1d9`. The Redis readiness probe is bounded at 2 s (#58). Qualified against OpenAI `gpt-4o-mini` only; deployment qualification (Gate C) is the product's (`docs/RELEASE-READINESS.md`).
- **Documentation and tests** (#44 to #50, #59 to #61): live multi-factor and Stripe plan-change evidence, ADR status updates, the D1 to D14 local rehearsal records.

Migration head: `f6a2c8e4b1d9`. All six migrations are additive. Before upgrading, read `docs/CONSUMER-GUIDE.md` section 14, "From `4197d2f` to v0.1.0".
