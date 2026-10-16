# ADR-0049: Multi-factor login for platform operators

Status: Accepted (2026-10-15) and implemented; validated on 2026-10-16 against a live login on the local development ZITADEL (Validation below); validation on the deployment's own instance is open — the repository owner authorized the recommended production hardening of the deferred ADR-0045 items.
Date: 2026-10-15
Supersedes / Superseded by: — (decides the "multi-factor or recent-authentication claims for operators" item ADR-0045 deferred)
Related: ADR-0005 (identity build versus buy), ADR-0045 (platform authority; decision D2, the fresh-session rule), ADR-0046 (claims kept on the session).

## Context

Platform operators hold installation-wide authority through the opt-in platform-admin router. ADR-0045 protects a route that changes authority with a fresh-session rule (D2): the presenting SaaS OS session must be at most 15 minutes old. It says itself that this "proves nothing about when the person last authenticated at the identity provider", and it deferred requiring multi-factor evidence because that makes authorization depend on an identity-provider claim.

Facts:

- The login callback already verifies the ID token and keeps one claim on the session: the verified email (ADR-0046).
- OIDC ID tokens may carry `amr` (RFC 8176, the authentication methods used) and `auth_time` (when the person last actively authenticated). The ZITADEL spike (`docs/architecture/PRODUCT-OWNED-AUTHENTICATION-ARCHITECTURE.md`, gate 4, v4.19.0) verified live: a password gives `["pwd"]`, password and TOTP give `["pwd","otp","mfa"]`, a login with no credential factor carries no `amr`. From ZITADEL's source only: a user-verified passkey gives `["user","mfa"]`, a security key alone `["user"]`. It also found that ZITADEL's own `forceMfa` policy does not stop a password-only session from completing a login, so the check here is the enforcement, not a second layer.
- The recovery command (`python -m saas_os.api.platform_bootstrap recover`) works without HTTP, so a deployment that locks operators out of the HTTP surface can always recover.

## Decision

1. **The session records what the provider asserted.** At login, `amr` decides a boolean `core.sessions.multi_factor`, and `auth_time` is kept as `core.sessions.provider_authenticated_at`. Migration `b5d2f7a9c3e1`, additive.
2. **What counts as more than one factor** (`saas_os.core.identity.oidc.is_multi_factor`): `mfa`, or a password (`pwd`) together with a possession or inherence factor (`otp`, `hwk`, `swk`, `sms`, `tel`, `sc`, biometric methods). Not `user` alone (user presence, a security key on its own) and not `pin` (a second knowledge factor). Absent, malformed or single-factor: not multi-factor. The claim is trusted only from a verified ID token.
3. **A deployment can require it for every platform-admin route**: `PLATFORM_OPERATOR_REQUIRE_MFA` (`true`/`false`; unset means `true` with `ENVIRONMENT=production`, `false` otherwise). When true, an operator's request on any platform route, read or write, whose session is not multi-factor is `401` with `X-Error-Code: multi_factor_required`, and a `denied` platform audit row is written on a best-effort basis (`record_platform_refusal`, as for every route refusal); the operator logs in again with a second factor. The check runs after the operator check, so a non-operator still gets the `404` of an unknown path and learns nothing.
4. **Production requires it by default**, in the application and in `docker-compose.prod.yml`. A deployment opts out by setting the variable to `false`.
5. **The fresh-session rule is unchanged.** It still measures the SaaS OS session. `provider_authenticated_at` is recorded as evidence but not enforced: enforcing it would need the login to force re-authentication at the provider (`prompt=login` or `max_age`), which the login flow does not request today; without that, an operator with a long provider session could never satisfy it.

## Consequences

- An operator must enroll a second factor (or a passkey) in ZITADEL before using the platform-admin router in production.
- If the instance's ID tokens do not carry `amr`, every operator is refused on the HTTP surface until the deployment sets `PLATFORM_OPERATOR_REQUIRE_MFA=false` or fixes the provider configuration; the recovery command is unaffected. A live login on the local development ZITADEL produced a multi-factor session (Validation below); verifying `amr` on the deployment's own instance, with its own login policy, remains an open validation item.
- Sessions issued before the migration are not multi-factor; operators log in again.
- The evidence is fixed when the session is issued: removing a person's second factor at the provider does not change sessions already issued. They end at expiry or when revoked (`revoke_user_sessions`); revoke an operator's sessions when their factors change.
- Tenant users are unaffected: the setting applies to platform-admin routes only.

## Validation

Live, 2026-10-16, on the local development stack (`docker-compose.yml`, ZITADEL `v4.19.0`, `docs/LOCAL-IDENTITY.md`), by the repository owner logging in through `GET /auth/login`:

- **Factors at the provider.** The owner enrolled an authenticator app (TOTP) on the local instance admin. ZITADEL's event store recorded `user.human.mfa.otp.added`, `user.human.mfa.otp.verified`, and `user.human.mfa.otp.check.succeeded` at each of the two logins that asked for credentials.
- **What SaaS-OS recorded.** The callback issued four sessions for the same user, every one with `core.sessions.multi_factor = true` and a verified email. `provider_authenticated_at` matched the provider's authentication time: two later logins that reused ZITADEL's existing login session carry the earlier time, not their own. That is the value step 4a's freshness rule is meant to see.
- **Not observed.** The `amr` list itself was not captured: SaaS-OS does not log claims, and logging was not added for this. The parametrised case in `tests/core/identity/test_oidc.py` pins `["pwd", "otp", "mfa"]`. Step 4a itself was exercised the same day ("The rule on a platform-admin route" below).
- **Single factor, same day.** The owner created a second local user with a verified email and a password only, and logged in with it. ZITADEL recorded `user.human.password.check.succeeded` and then `user.human.mfa.init.skipped`: the owner skipped the offer to set up a second factor, because the local default login policy does not require one. SaaS-OS issued that user's session with `multi_factor = false`, a verified email, and `provider_authenticated_at` equal to the password check. With `PLATFORM_OPERATOR_REQUIRE_MFA=true`, step 4a would refuse that session on a platform-admin route.
- **A reused provider login.** A later `GET /auth/login` in a browser that still held ZITADEL's login session for the first user produced a new SaaS-OS session for that user without any prompt. It kept the earlier `provider_authenticated_at` (11:18:12), not the time of the new session.
- **The rule on a platform-admin route, same day.** The local deployment's first owner was bootstrapped for the admin user (`python -m saas_os.api.platform_bootstrap bootstrap`). The password-only user was enrolled with `platform.operator:read` alone, through `recover`, so that both are operators and only the factor differs. A second local process served `create_app()` with `build_platform_admin_router()` mounted, `PLATFORM_ADMIN_HTTP_ENABLED=true` and `PLATFORM_OPERATOR_REQUIRE_MFA=true`. `GET /v1/platform/operators` with each browser's session:
  - **Admin, with the multi-factor session:** `200` with both operators. The audit shows `platform.operator.read` with outcome `success`.
  - **Password-only operator:** `401` with the generic `Authentication required.`. The audit shows `platform.operator.read` with outcome `denied` and reason `multi_factor_required`.
  - **Both:** each login by an operator was recorded as `platform.operator.session_issued`. The two operators and their grants remain in the local development database only.
- **Still open.** This was the local instance's default login policy, not a deployment's. Before relying on `PLATFORM_OPERATOR_REQUIRE_MFA=true` in production, repeat the check on the deployment's own ZITADEL with its own policy (RUNBOOKS section 1). An identity-provider login (for example Google) may report other `amr` values and needs its own check.

## Implementation

- `saas_os/core/identity/oidc.py`: `VerifiedIdentity.multi_factor`, `VerifiedIdentity.authenticated_at`, `is_multi_factor()`.
- `saas_os/core/identity/models.py` and `sessions.py`: the two columns; `issue_session(..., multi_factor=, provider_authenticated_at=)`. `saas_os/api/auth/routes.py`: the callback passes them.
- `saas_os/api/platform_admin/config.py`: `PLATFORM_OPERATOR_REQUIRE_MFA` (exactly `true` or `false`). `saas_os/api/dependencies.py::require_platform_permission`: step 4a. `saas_os/api/errors.py::multi_factor_required`.
- Tests: `tests/core/identity/test_oidc.py` (which `amr` values count; `auth_time`), `tests/api/auth/test_auth_routes_unit.py` (the callback records both), `tests/api/test_platform_admin_unit.py` (the rule on read and fresh routes, a non-operator's 404, the setting's values), `tests/core/platform_authority/test_platform_admin_routes_integration.py` (end to end with real sessions and the audit row), `tests/infra/db/test_session_authentication_evidence_migration.py`.

## Not decided here

- Forcing re-authentication at the provider for authority-changing routes (`prompt=login` / `max_age`), which would let the fresh-session rule measure the provider authentication.
- Requiring multi-factor for tenant administrators.
