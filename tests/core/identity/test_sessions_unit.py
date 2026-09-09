"""Pure unit tests for `core/identity/sessions.py`'s token-hashing
mechanics (docs/IMPLEMENTATION-ROADMAP.md Phase 3.2 section 9) -- no
database needed, since these only exercise the hash function and entropy
size, not persistence. Database-backed lifecycle tests (issue/validate/
expire/revoke against real PostgreSQL) live in
tests/core/identity/test_identity_integration.py.
"""

from __future__ import annotations

import hashlib

from core.identity.sessions import _TOKEN_BYTES, _hash_token


def test_hash_token_is_deterministic() -> None:
    assert _hash_token("same-raw-token") == _hash_token("same-raw-token")


def test_hash_token_differs_for_different_input() -> None:
    assert _hash_token("token-a") != _hash_token("token-b")


def test_hash_token_matches_sha256_hex_digest() -> None:
    raw = "a-raw-bearer-token"
    assert _hash_token(raw) == hashlib.sha256(raw.encode("utf-8")).hexdigest()


def test_hash_token_never_contains_the_raw_value() -> None:
    """Cheap but real: a SHA-256 hex digest of a short-ish token
    essentially never contains the raw token as a substring; this guards
    against a hashing implementation mistake (e.g. accidentally
    concatenating instead of hashing)."""
    raw = "a-raw-bearer-token-that-is-reasonably-long"
    assert raw not in _hash_token(raw)


def test_token_byte_length_meets_the_256_bit_minimum() -> None:
    """docs/IMPLEMENTATION-ROADMAP.md Phase 3.2 section 9: 'random opaque
    session secret' -- 256 bits (32 bytes) is the platform's stated
    minimum entropy for a bearer secret."""
    assert _TOKEN_BYTES >= 32
