# ADR-0046: Invitation acceptance over HTTP, bound to a verified email

Status: Accepted (2026-10-14) and implemented — option B chosen by the repository owner.
Date: 2026-10-14
Supersedes / Superseded by: — (closes gap G2 of [ADR-0040](0040-reusable-http-platform-capabilities.md))

## Context

ADR-0040 left accepting an invitation unexposed (gap G2) and listed four questions. The facts, verified against the code at `8b5e458`:

- `accept_invitation(raw_token, tenant_id, *, caller)` was complete in Core: one use, aware of expiry and revocation, row-locked, fenced against closed tenants, audited as `invitation.accept`, and every failure was the same `InvitationInvalidError`. `tenant_id` only scopes the lookup under row-level security; it is never authority. An existing membership that is not active is refused, not reactivated.
- Core did not check that the person accepting is the person invited, and said so: `core.users` stores no email, by design, and an email must never become an identity key.
- At login the ID token's `email` claim was read and then discarded. `email_verified` was never read, and login requested only the `openid` scope, so most providers sent no email at all.
- The route policy ADR-0040's first question asked for already existed: `authenticated` (`get_current_actor`, `get_current_session`), a signed-in user who need not be a member.
- ADR-0044's origin check already covered every unsafe method authenticated by the session cookie.
- Under the authorization-code flow ZITADEL, the bundled identity provider, puts the `email` scope's claims only in userinfo, not in the ID token, unless the application's `id_token_userinfo_assertion` option is set (`proto/zitadel/application/v2/oidc.proto`, field 15, at v4.19.0). SaaS OS reads the ID token alone.

## Options Considered

### Option A — the token alone
Whoever holds the link and is signed in joins.
- Advantages: simplest; no stored email; matches Core as it was.
- Disadvantages: a forwarded or leaked link lets someone else join, and a person signed in to a second account joins with that one. The tenant learns of it only from its member list.

### Option B — a verified email, captured at login
Login also requests the `email` scope. The email the provider asserted and verified is kept on the session. Acceptance requires it to equal the invited email.
- Advantages: binds the invitation to the person it was sent to; the login callback changes only by passing one value on; the email lives exactly as long as the session.
- Disadvantages: one additive migration; an email stored as personal data on sessions; a provider that does not verify emails, or does not put them in the ID token, cannot be used to accept invitations (fail closed); some providers show a consent prompt for the extra scope.

### Option C — a verified email, checked by a fresh login
The invitation link starts a login whose callback compares the email and accepts.
- Advantages: nothing stored on sessions.
- Disadvantages: changes the authentication callback, keeps the raw invitation token in the login transaction, and forces a login even on someone already signed in.

## Recommendation

Option B.

## Decision

The repository owner chose option B on 2026-10-14. Implemented as follows.

1. **The claim.** `VerifiedIdentity.email_verified` is `True` only when the ID token carries `email_verified` as the JSON boolean `true` (OIDC Core 5.1); absent, `false`, a string or a number is not a verification. Login requests the scopes `openid email`.
2. **The session.** `core.sessions.verified_email` (`varchar(320)`, nullable; migration `3654bebb24c7`) holds the email, trimmed and case-folded like an invitation's `invited_email`, only when the provider verified it and it is an ASCII string; otherwise `NULL`. Case folding maps distinct non-ASCII addresses onto one (`ß` and `ss`), so a non-ASCII address is never used to bind an invitation: such a person cannot accept over HTTP. It is compared, never used to find a user, and `core.users` still stores no email. Revoking the session (logout) clears it at once; the row itself is deleted by session retention and by identity erasure (`purge_user_sessions`).
3. **Core.** `accept_invitation(..., accepting_email=None)`. When given, the invitation is accepted only if `accepting_email`, normalized, equals `invited_email`, and both are ASCII. The comparison is constant-time and runs under the invitation's row lock, after the token, tenant and lifecycle checks and before anything is consumed. A mismatch is the same `InvitationInvalidError` as every other refusal. When `None`, nothing is compared: a product's own acceptance path that binds the person another way is unchanged.
4. **The route.** `POST /v1/tenants/{tenant_id}/invitations/accept` with body `{"token": "..."}`, in a separate opt-in router, `invitation_acceptance_router` (`saas_os/api/v1/invitation_acceptance.py`). It is separate because its rules are the opposite of the capability routers': the policy is `authenticated` with no tenant permission, and the tenant in the path scopes the lookup instead of granting authority. A session with no verified email is refused before Core is called. Success is `200` with `{"tenant_id", "status"}`.
5. **One answer.** Every refusal is `404 {"detail": "invitation not found."}`: an unknown, used, revoked or expired token; a tenant that is not the invitation's, does not exist, or no longer admits members; no verified email; another email; an existing suspended membership.
6. **The edge.** No credential is `401`. A cookie-authenticated request from another origin is `403` (ADR-0044). One rate-limit bucket per signed-in user for this route (`invitation-accept:<user id>`), failing closed (`429`; `503` when the limiter cannot answer). There is no limit by client address: the route needs a session, every login is already limited by address, and the token has 256 bits.
7. **No preview.** No route shows an invitation or its tenant before acceptance; the product's own email names the tenant.
8. **The bundled identity provider.** `saas-os-local-identity` creates the ZITADEL application with `idTokenUserinfoAssertion` set, and turns it on, by one in-place update that changes nothing else, for an application created before. ZITADEL's own documentation notes that this option departs from OIDC Core, which places those claims in userinfo once an access token is issued. The departure is confined to this deployment's own application and is the smallest change that lets SaaS OS read the claim from the token it already validates.

**A deployment using another provider** must put `email` and `email_verified` in the ID token for the `email` scope. Most do. Where a provider does not, the route refuses every acceptance; reading userinfo instead is recorded as a follow-up in the deferred ledger.

## Consequences

- Sessions issued before the migration, or by a provider that does not verify the email, cannot accept an invitation over HTTP. The user logs in again after the deployment is updated.
- `invitations_router` is unchanged; a product adds `invitation_acceptance_router` next to it.
- Accepting changes no audit shape: Core writes the same `invitation.accept` event in the tenant's trail.

## What Would Be Difficult to Change Later

- Removing the email binding would silently widen who can join a tenant. Any relaxation needs its own decision.
- `verified_email` on sessions is a stored copy of personal data. Moving it elsewhere is easy; making it an identity key would contradict the identity model's rule that an email is never the identity key (`core.users`, `saas_os/core/identity/models.py`) and is not intended.

## Related

[ADR-0040](0040-reusable-http-platform-capabilities.md) (gap G2), [ADR-0044](0044-same-origin-check-for-cookie-authenticated-mutations.md) (origin check), [ADR-0031](0031-foundation-authority-and-evidence.md) (the explicit user caller), [ADR-0023](0023-self-hosted-provider-neutral-identity-invisible-zitadel.md) and [ADR-0025](0025-same-origin-zitadel-login-v2-topology.md) (the bundled provider), `docs/architecture/HTTP-CAPABILITY-MATRIX.md`, `docs/CONSUMER-GUIDE.md`.

Tests: `tests/api/v1/test_invitation_acceptance_integration.py` (with a negative control), `tests/infra/db/test_sessions_verified_email_migration.py`, `tests/core/identity/test_oidc.py`, `tests/api/auth/test_auth_routes_unit.py`, `tests/infra/local_identity/test_local_identity_bootstrap_unit.py`.
