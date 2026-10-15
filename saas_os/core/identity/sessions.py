"""Platform session lifecycle (docs/IMPLEMENTATION-ROADMAP.md Phase 3.2;
docs/SECURITY.md: session secrets are stored hashed, never in plaintext).

A session's bearer secret exists in plaintext only at issuance -- the
caller (the HTTP layer, `saas_os/api/auth/routes.py::callback`, which sets it as
the HttpOnly session cookie) receives it once and is responsible for
getting it to the client; the platform stores only a SHA-256 hash
(`core.sessions.token_hash`). This mirrors the general
secret-handling discipline elsewhere in the platform (docs/SECURITY.md)
and the hashed-credential pattern anticipated for `core/api-keys`
(docs/IMPLEMENTATION-ROADMAP.md Phase 4.1).

Sessions are global (`saas_os/core/identity/models.py`'s docstring) -- every
function here uses `saas_os.infra.db.session_scope()`, never
`tenant_session_scope()`.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta

from saas_os.core.identity.errors import (
    InactiveUserError,
    SessionExpiredError,
    SessionNotFoundError,
    SessionRevokedError,
)
from saas_os.core.identity.models import Session, User
from saas_os.infra.db import select, session_scope

# 256 bits of entropy -- the standard, non-guessable bearer-secret size
# (docs/IMPLEMENTATION-ROADMAP.md Phase 3.2 section 9: "random opaque
# session secret").
_TOKEN_BYTES = 32
_DEFAULT_SESSION_LIFETIME = timedelta(hours=12)


def _hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def issue_session(
    user_id: uuid.UUID,
    *,
    lifetime: timedelta = _DEFAULT_SESSION_LIFETIME,
    verified_email: str | None = None,
    multi_factor: bool = False,
    provider_authenticated_at: datetime | None = None,
) -> tuple[Session, str]:
    """Issue a new platform session for `user_id`. Returns the persisted
    session record (never carrying the raw secret -- only its hash) and the
    raw bearer token. This is the ONLY point the raw value exists; it is
    never stored, logged, or reconstructable afterward.

    `verified_email` is the email the identity provider verified at this
    login, or `None`; it is stored normalized on the session and used only
    to accept an invitation addressed to it (ADR-0046).

    `multi_factor` and `provider_authenticated_at` record what the identity
    provider asserted about this login (its `amr` and `auth_time` claims,
    ADR-0049); the platform-admin router reads them.
    """
    if not isinstance(multi_factor, bool):
        raise TypeError("multi_factor must be a bool.")
    raw_token = secrets.token_urlsafe(_TOKEN_BYTES)
    token_hash = _hash_token(raw_token)
    now = datetime.now(UTC)

    with session_scope() as db_session:
        # ADR-0031: a session is never issued to an inactive user.
        # ADR-0045 section 11d: the user row is read FOR SHARE in the
        # inserting transaction. A deactivation takes that row exclusively
        # before it revokes sessions, so an issuance in flight makes it
        # wait and the row inserted here is committed and visible to its
        # revocation; an issuance that starts later waits, then reads
        # `is_active = false` and refuses. No live session can be inserted
        # behind a deactivation and become usable on reactivation.
        is_active = db_session.execute(
            select(User.is_active).where(User.id == user_id).with_for_update(read=True)
        ).scalar_one_or_none()
        if not is_active:
            raise InactiveUserError(user_id)
        record = Session(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=now + lifetime,
            verified_email=normalize_verified_email(verified_email),
            multi_factor=multi_factor,
            provider_authenticated_at=provider_authenticated_at,
        )
        db_session.add(record)
        db_session.flush()
        # ADR-0045 section 8: a session issued to an enrolled platform
        # operator is recorded in the platform audit, in this transaction.
        # Deferred import: that package imports `saas_os.core.identity`.
        from saas_os.core.platform_authority import (
            record_operator_session_issued_in_transaction,
        )

        record_operator_session_issued_in_transaction(
            db_session, user_id=user_id, session_id=record.id
        )
        db_session.refresh(record)
        db_session.expunge(record)
        return record, raw_token


def normalize_verified_email(email: object) -> str | None:
    """Trimmed and case-folded, the same normalization an invitation's
    `invited_email` receives; `None` for anything else: not a string,
    empty, over-long (RFC 5321 limits an address to 320 characters), or
    not ASCII. Case folding maps distinct non-ASCII addresses onto one
    (`ß` and `ss`, the Kelvin sign and `k`), and this value binds an
    invitation to a person (ADR-0046), so a non-ASCII address is never
    kept: such a person cannot accept over HTTP, which fails closed."""
    if not isinstance(email, str) or not email.isascii():
        return None
    normalized = email.strip().casefold()
    if not normalized or len(normalized) > 320:
        return None
    return normalized


def validate_session(raw_token: str) -> Session:
    """Resolve a raw bearer token to its session record, enforcing
    expiration and revocation.

    Looks up by the token's hash, never the raw value -- an unknown or
    malformed token and a hash that simply has no match both raise the
    same `SessionNotFoundError` (docs/IMPLEMENTATION-ROADMAP.md Phase 3.2
    section 9: "reject unknown sessions").
    """
    token_hash = _hash_token(raw_token)
    with session_scope() as db_session:
        record = db_session.execute(
            select(Session).where(Session.token_hash == token_hash)
        ).scalar_one_or_none()
        if record is None:
            raise SessionNotFoundError()
        if record.revoked_at is not None:
            session_id = record.id
            db_session.expunge(record)
            raise SessionRevokedError(session_id)
        if record.expires_at <= datetime.now(UTC):
            session_id = record.id
            db_session.expunge(record)
            raise SessionExpiredError(session_id)
        # ADR-0031: checked live on every validation -- an existing session
        # stops authenticating the moment its user is deactivated. The
        # session row is not revoked here; while the user is inactive it is
        # unusable, and it still expires on its own schedule.
        user = db_session.get(User, record.user_id)
        if user is None or not user.is_active:
            user_id = record.user_id
            db_session.expunge(record)
            raise InactiveUserError(user_id)
        db_session.expunge(record)
        return record


def revoke_session(session_id: uuid.UUID) -> None:
    """Revoke a session by id. Idempotent: revoking an already-revoked
    session is a no-op, not an error -- a caller retrying a revocation
    (e.g. after a network timeout) must not be surprised by a failure."""
    with session_scope() as db_session:
        record = db_session.get(Session, session_id)
        if record is None:
            raise SessionNotFoundError()
        if record.revoked_at is None:
            record.revoked_at = datetime.now(UTC)
        # ADR-0046: a revoked session keeps no verified email while it waits
        # for retention to delete it.
        record.verified_email = None


def purge_user_sessions(user_id: uuid.UUID) -> int:
    """RA-12-3 -- delete every `core.sessions` row belonging to `user_id`
    -- the global (not tenant-scoped) second step of
    `saas_os.core.identity.erasure.erase_user_identity()`. Nothing references
    `core.sessions` (no incoming foreign key targets it), so this is a
    clean leaf deletion; a raw bearer token whose row is gone fails
    `validate_session()`'s own lookup with the same `SessionNotFoundError`
    an unknown token already produces -- no new authentication code path
    is needed for the erased identity to stop being usable this way.
    Idempotent: a second call finds nothing and returns 0.
    """
    deleted = 0
    with session_scope() as db_session:
        rows = (
            db_session.execute(
                select(Session)
                .where(Session.user_id == user_id)
                .order_by(Session.id)
                .with_for_update()
            )
            .scalars()
            .all()
        )
        for row in rows:
            db_session.delete(row)
            deleted += 1
    return deleted
