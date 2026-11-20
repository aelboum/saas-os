# ADR-0064: OpenID Connect RP-initiated logout

Status: Accepted (2026-11-20, owner work package "SaaS-OS – Implement RP-Initiated Logout (P2-F1)"). Implemented on branch `feat/rp-initiated-logout`; not merged, not released.
Date: 2026-11-20
Supersedes / Superseded by: none. Narrows one sentence of ADR-0023 and of `docs/architecture/AUTHENTICATION-BOUNDARY-REVIEW.md` section 11.5 (below); ADR-0026 stays rejected.
Related: ADR-0005 (identity build vs buy), ADR-0019 (field encryption), ADR-0023 (provider-neutral identity boundary), ADR-0024 (single-origin runtime), ADR-0025 (same-origin ZITADEL Login V2), ADR-0026 (rejected embedded login), ADR-0044 (same-origin check for cookie mutations), ADR-0046 (verified email on the session).

## Context

A consuming product (finding P2-F1, severity Medium) reported: after "sign out", "sign in" on the same browser returned the user without a password. `POST /auth/logout` revoked the SaaS-OS session and cleared its cookie, but the identity provider's own browser session survived, so the next authorization request was answered by single sign-on. On a shared computer the next person is signed in as the previous one.

This was known and documented as intended: section 11.5 of the authentication boundary review recorded, live, that `POST /auth/logout` ends only the SaaS-OS session and that `/oidc/v1/end_session` with a hint ends the ZITADEL session. `IdentityProvider` (ADR-0023) listed provider-side logout as out of scope. ADR-0026, which would have ended provider sessions server-side, was rejected on 2026-10-16.

What the code had before this ADR:

- Discovery read `authorization_endpoint`, `token_endpoint` and `jwks_uri`; not `end_session_endpoint`.
- The ID token was validated in the callback and then discarded. `core.sessions` stored the SHA-256 of the session secret, the verified email (ADR-0046) and the `amr`/`auth_time` facts (ADR-0049); nothing that identifies the provider session.
- No post-logout redirect URI was configured, and the local ZITADEL bootstrap registered none.

## Decision

SaaS-OS implements OpenID Connect RP-Initiated Logout 1.0 as a browser redirect, opt-in per deployment. It stays a pure OIDC relying party (ADR-0025): no provider API call, no provider credential, nothing ZITADEL-specific.

1. **Configuration.** One new, optional, non-secret setting, `OIDC_POST_LOGOUT_REDIRECT_URI`. Unset (the default) means RP-initiated logout is off and every existing behaviour is unchanged. Set, it must be an absolute `http(s)` URL on the application's own origin (the origin of `PUBLIC_APP_ORIGIN`, or of the callback when only `OIDC_REDIRECT_URI` is set), `https` in production, with no credentials, no fragment, no whitespace or backslash. A bad value fails the auth configuration closed, like every other auth setting. It is never taken from a request.
2. **Discovery.** `end_session_endpoint` is read from the same discovery document as the other endpoints, with the same scheme rule (`https`, or `http` only for an `http` development issuer). Absent means the provider offers no RP-initiated logout; present but unusable is a configuration error.
3. **The ID token as hint.** When the setting is present, the callback keeps the ID token of that login on the session it issues, in a new nullable column `core.sessions.id_token_hint_ciphertext`, encrypted with the existing `EncryptionService` (ADR-0019) and bound to the row's id as associated data, so a ciphertext moved to another row does not decrypt. It is cleared by every revocation (`revoke_session`, the new `revoke_session_for_logout`), and the row is removed by session retention and by identity erasure as before. When no field-encryption key is available the login still succeeds, nothing is stored, and an error is logged (`auth_id_token_hint_not_stored`); the logout then sends `client_id` without a hint.
4. **A new route, `POST /auth/logout/redirect`,** for an ordinary HTML form (a top-level navigation, so no token ever reaches script):
   1. The ADR-0044 same-origin check runs on every request, with or without a cookie. Anything else is `403` and changes nothing.
   2. The session named by the cookie is looked up by the hash of its secret and, if not yet revoked, revoked and its hint taken out of the row in one committed transaction, before anything else. This includes an expired session and one whose user is inactive: their application session is already unusable, but the provider's may not be, and the caller proved possession of the secret, the proof every authentication accepts. A missing, unknown or already revoked session is not an error and yields no hint. The lookup sits behind the existing failed-credential limit (`429`).
   3. The cookie is cleared on every outcome.
   4. With the setting present and an `end_session_endpoint` discovered: `303` to that endpoint with `client_id`, `post_logout_redirect_uri` and, when available, `id_token_hint`. Otherwise (no endpoint, or discovery fails): `303` to the same-origin path of the configured URI, or `/`.
   5. `Cache-Control: no-store` and `Referrer-Policy: no-referrer` on the response. The `Authorization` header is ignored: this is a cookie flow.
5. **`POST /auth/logout` is unchanged** (`204`, authenticated, for fetch and API clients). It now also clears the stored hint. Products choose which route their sign-out button uses.
6. **No `state`, no callback.** SaaS-OS takes no action when the browser returns to the post-logout URI, so there is nothing to bind or replay. The URI is a plain page of the product.
7. **Events.** Login and logout happen before any tenant is known and `core.audit_log` requires a tenant, so, as for the existing `auth_logout`, the evidence is structured log events: `auth_logout_initiated`, `auth_logout_local_completed`, `auth_logout_idp_redirected` (with a boolean saying whether a hint was sent), `auth_logout_idp_unavailable`, `auth_logout_local_only`. They carry the user id, session id and a reason; never a token, a cookie or the end-session URL.
8. **`IdentityProvider`** gains one method, `build_end_session_url(post_logout_redirect_uri, id_token_hint) -> str | None` (pure, no I/O). Server-side termination of provider sessions stays out of scope.

### What a successful logout does and does not end

| | Ended |
|---|---|
| The SaaS-OS session of this browser | Always, before the redirect |
| The provider's session for this browser | When the provider honours the request (verified for ZITADEL, see Validation) |
| Other SaaS-OS sessions of the same user (other browsers) | No. `POST /auth/logout` and this route revoke only the current session |
| Sessions of other applications at the same provider | Not claimed. Whether the provider also signs the browser out of other clients is the provider's behaviour; SaaS-OS implements no front- or back-channel logout |

## Security

- **Open redirect:** the only destinations are the discovered endpoint (from the configured issuer's own discovery document, which must name that issuer) and the configured URI or its path. Neither comes from the request.
- **CSRF:** a cross-site or sibling-origin post is `403` before anything happens, cookie or not. A logout CSRF therefore cannot sign a user out, and cannot be used to bounce a browser through the provider.
- **Token leakage:** the ID token is stored only encrypted, leaves the server only as the `id_token_hint` query parameter of the `Location` header (which OIDC requires), and is never logged (the redaction lists already contain `id_token`). `no-referrer` keeps the provider URL out of a later request's `Referer`. The provider sees the token it issued itself.
- **Provider outage:** the local revocation commits first, so an unreachable provider can only leave the provider's own session alive, the state before this ADR.
- **Personal data:** an ID token carries the subject and, when asserted, the email claims. Stored encrypted, cleared at logout, deleted with the session.
- **Expired sessions:** a session past its 12 hours cannot authenticate any request, but the browser logout still ends it and still sends its hint, because the provider's session can outlive it. Once retention has deleted the row, or after a revocation, there is no hint; the logout then sends `client_id` only, and whether the provider ends its session without a hint is its behaviour (ZITADEL's hosted login did not, per section 11.5 of the boundary review).
- **Who receives the hint:** whoever presents the session secret receives that session's ID token in the `Location` header. That is the session's owner, or someone who already stole the secret (who could use a valid one for everything else).

## Consequences

- One additive migration (`8db003ab849e`). Catalog-only `ADD COLUMN`; existing sessions get `NULL`.
- The public API changes: a new method on the `IdentityProvider` protocol, a new field on `OIDCFlowEndpoints`, a new `issue_session` keyword, and new `revoke_session_for_logout`, `LogoutRevocation` and `build_end_session_url`. A product that implements `IdentityProvider` itself must add the method. A minor release (ADR-0015).
- A product enables it by setting `OIDC_POST_LOGOUT_REDIRECT_URI`, registering the same URI at the provider, configuring field encryption, and pointing its sign-out button at a form post to `/auth/logout/redirect`.

## Validation

Recorded in `docs/P-ROADMAP.md` (the ADR-0064 entry): unit and integration tests, negative controls, and a Chromium end-to-end run against a local ZITADEL.

## Alternatives considered

- **A JSON response carrying the end-session URL for a `fetch` client.** Rejected: the URL contains the ID token, which would then be readable by script.
- **`prompt=login` on every authorization request.** Forces a password each time but leaves the provider session alive; it hides the symptom. Could be added later as a separate option.
- **Server-side termination through a provider API (ADR-0026).** Rejected on 2026-10-16 and not reopened.
- **Storing the token unencrypted, or a provider session id instead.** The first stores a credential-shaped value in clear; the second is provider-specific and still needs the provider to accept it.
