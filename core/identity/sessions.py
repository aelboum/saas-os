"""Platform session lifecycle (docs/IMPLEMENTATION-ROADMAP.md Phase 3.2;
docs/SECURITY.md: session secrets are stored hashed, never in plaintext).

A session's bearer secret exists in plaintext only at issuance -- the
caller (the future HTTP layer, Phase 8) receives it once and is
responsible for persisting it client-side; the platform stores only a
SHA-256 hash (`core.sessions.token_hash`). This mirrors the general
secret-handling discipline elsewhere in the platform (docs/SECURITY.md)
and the hashed-credential pattern anticipated for `core/api-keys`
(docs/IMPLEMENTATION-ROADMAP.md Phase 4.1).

Sessions are global (`core/identity/models.py`'s docstring) -- every
function here uses `infra.db.session_scope()`, never
`tenant_session_scope()`.
"""

from __future__ import annotations

import hashlib
import secrets
import uuid
from datetime import UTC, datetime, timedelta

from core.identity.errors import SessionExpiredError, SessionNotFoundError, SessionRevokedError
from core.identity.models import Session
from infra.db import select, session_scope

# 256 bits of entropy -- the standard, non-guessable bearer-secret size
# (docs/IMPLEMENTATION-ROADMAP.md Phase 3.2 section 9: "random opaque
# session secret").
_TOKEN_BYTES = 32
_DEFAULT_SESSION_LIFETIME = timedelta(hours=12)


def _hash_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()


def issue_session(
    user_id: uuid.UUID, *, lifetime: timedelta = _DEFAULT_SESSION_LIFETIME
) -> tuple[Session, str]:
    """Issue a new platform session for `user_id`. Returns the persisted
    session record (never carrying the raw secret -- only its hash) and the
    raw bearer token. This is the ONLY point the raw value exists; it is
    never stored, logged, or reconstructable afterward.
    """
    raw_token = secrets.token_urlsafe(_TOKEN_BYTES)
    token_hash = _hash_token(raw_token)
    now = datetime.now(UTC)

    with session_scope() as db_session:
        record = Session(user_id=user_id, token_hash=token_hash, expires_at=now + lifetime)
        db_session.add(record)
        db_session.flush()
        db_session.refresh(record)
        db_session.expunge(record)
        return record, raw_token


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
