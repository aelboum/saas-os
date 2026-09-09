"""OIDC login-transaction lifecycle (P2.2): the server-side, single-use
record binding an Authorization Code Flow callback to the browser that
started it (`core/identity/models.py::LoginTransaction`).

`begin_login_transaction()` generates the three per-login secrets --
`state`, `nonce`, and the PKCE `code_verifier` -- with
`secrets.token_urlsafe(32)` (256 bits of `os.urandom`-backed entropy,
the same generator and size `core/identity/sessions.py` already uses for
session secrets; 43 URL-safe characters, inside RFC 7636's 43..128
verifier length). It returns the persisted row plus the derived PKCE
`code_challenge` (`S256`: base64url, unpadded, of SHA-256 of the
verifier) -- the *only* PKCE value that may appear in the authorization
URL. `plain` is never produced or accepted anywhere in this module.

`consume_login_transaction()` is the single-use guarantee: it loads the
row with a row lock (`SELECT ... FOR UPDATE`), checks expiry and a
constant-time `state` comparison, and *deletes* the row in the same
transaction. Two concurrent callbacks for one transaction serialize on
the lock; the second finds no row and fails. Every failure -- unknown id,
expired, already consumed, state mismatch -- raises the same
`LoginTransactionInvalidError`, so a caller probing the callback learns
nothing about which check failed. The state, nonce, and verifier are
never logged and never appear in any exception.

Global, untenanted (`infra.db.session_scope()`), mirroring
`core/identity/sessions.py`: a login transaction exists before any user
or tenant is known.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from core.identity.errors import LoginTransactionInvalidError
from core.identity.models import LoginTransaction
from infra.db import select, session_scope

_SECRET_BYTES = 32
_DEFAULT_LIFETIME = timedelta(minutes=10)
PKCE_CODE_CHALLENGE_METHOD = "S256"


@dataclass(frozen=True)
class StartedLogin:
    """What a login initiator needs and nothing more: the transaction id
    (goes into the browser's HttpOnly transaction cookie), the `state`
    and `nonce` (go to the provider), and the derived `code_challenge`.
    The `code_verifier` is deliberately absent -- it stays in the
    database until the callback's server-side exchange needs it."""

    transaction_id: uuid.UUID
    state: str
    nonce: str
    code_challenge: str
    expires_at: datetime


@dataclass(frozen=True)
class ConsumedLogin:
    """The values a callback needs once the transaction has been
    validated and deleted: the `nonce` to check against the ID token and
    the `code_verifier` for the token exchange."""

    transaction_id: uuid.UUID
    nonce: str
    code_verifier: str


def derive_code_challenge(code_verifier: str) -> str:
    """RFC 7636 `S256`: BASE64URL(SHA256(ASCII(code_verifier))), no padding."""
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def begin_login_transaction(*, lifetime: timedelta = _DEFAULT_LIFETIME) -> StartedLogin:
    state = secrets.token_urlsafe(_SECRET_BYTES)
    nonce = secrets.token_urlsafe(_SECRET_BYTES)
    code_verifier = secrets.token_urlsafe(_SECRET_BYTES)
    expires_at = datetime.now(UTC) + lifetime

    with session_scope() as session:
        record = LoginTransaction(
            state=state, nonce=nonce, code_verifier=code_verifier, expires_at=expires_at
        )
        session.add(record)
        session.flush()
        session.refresh(record)
        transaction_id = record.id

    return StartedLogin(
        transaction_id=transaction_id,
        state=state,
        nonce=nonce,
        code_challenge=derive_code_challenge(code_verifier),
        expires_at=expires_at,
    )


def consume_login_transaction(
    transaction_id: uuid.UUID, state: str, *, now: datetime | None = None
) -> ConsumedLogin:
    """Validate and atomically retire one transaction (module docstring).
    `now` is a test-only injection point; real callers never pass it."""
    if not isinstance(transaction_id, uuid.UUID) or not state:
        raise LoginTransactionInvalidError()
    current_time = now if now is not None else datetime.now(UTC)

    # The delete must actually commit even when the transaction turns out
    # to be invalid -- `session_scope()` rolls back on any exception
    # raised *inside* its `with` block, which would otherwise silently
    # undo the delete below and leave a mismatched/expired row available
    # for a second attempt. So: delete unconditionally inside the
    # transaction (letting it commit normally), then raise *after* the
    # block if the transaction did not actually validate.
    with session_scope() as session:
        record = session.get(LoginTransaction, transaction_id, with_for_update=True)
        if record is None:
            raise LoginTransactionInvalidError()

        nonce = record.nonce
        code_verifier = record.code_verifier
        expired = record.expires_at <= current_time
        state_matches = hmac.compare_digest(record.state.encode(), state.encode())
        session.delete(record)

    if expired or not state_matches:
        raise LoginTransactionInvalidError()

    return ConsumedLogin(transaction_id=transaction_id, nonce=nonce, code_verifier=code_verifier)


def purge_expired_login_transactions(now: datetime | None = None) -> int:
    """Delete every transaction past `expires_at`. Correctness never
    depends on this running -- `consume_login_transaction()` refuses an
    expired row regardless -- it only bounds storage growth from logins
    that were started and never completed."""
    current_time = now if now is not None else datetime.now(UTC)
    deleted = 0
    with session_scope() as session:
        stale = (
            session.execute(
                select(LoginTransaction).where(LoginTransaction.expires_at < current_time)
            )
            .scalars()
            .all()
        )
        for record in stale:
            session.delete(record)
            deleted += 1
    return deleted
