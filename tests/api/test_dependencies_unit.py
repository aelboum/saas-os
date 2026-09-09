"""Pure unit tests for `api.dependencies.get_current_actor`'s header
parsing -- no database needed (`core.identity.sessions.validate_session`
is monkeypatched so these tests exercise only the header-shape logic,
not session persistence, which the real-DB integration suite covers).
"""

from __future__ import annotations

import uuid

import pytest
from api.dependencies import get_current_actor
from api.errors import unauthorized
from core.identity.errors import SessionExpiredError, SessionNotFoundError, SessionRevokedError
from fastapi import HTTPException

pytestmark = pytest.mark.anyio


async def test_missing_authorization_header_is_rejected() -> None:
    with pytest.raises(HTTPException) as excinfo:
        await get_current_actor(authorization=None)
    assert excinfo.value.status_code == 401


async def test_non_bearer_scheme_is_rejected() -> None:
    with pytest.raises(HTTPException) as excinfo:
        await get_current_actor(authorization="Basic dXNlcjpwYXNz")
    assert excinfo.value.status_code == 401


async def test_bearer_with_no_token_is_rejected() -> None:
    with pytest.raises(HTTPException) as excinfo:
        await get_current_actor(authorization="Bearer ")
    assert excinfo.value.status_code == 401


async def test_valid_bearer_token_resolves_to_user_id(monkeypatch: pytest.MonkeyPatch) -> None:
    import api.dependencies as deps

    expected_user_id = uuid.uuid4()

    class _FakeSession:
        user_id = expected_user_id

    def _fake_validate_session(raw_token: str):
        assert raw_token == "a-real-looking-token"
        return _FakeSession()

    monkeypatch.setattr(deps, "validate_session", _fake_validate_session)

    actor_id = await get_current_actor(authorization="Bearer a-real-looking-token")
    assert actor_id == expected_user_id


@pytest.mark.parametrize(
    "exc_cls",
    [SessionNotFoundError, SessionExpiredError, SessionRevokedError],
)
async def test_invalid_session_states_all_map_to_the_same_401(
    monkeypatch: pytest.MonkeyPatch, exc_cls: type[Exception]
) -> None:
    """Non-enumeration: invalid/expired/revoked all produce the exact
    same generic 401 -- proven by asserting identical status+detail
    across all three, not just individually."""
    import api.dependencies as deps

    def _raise(raw_token: str):
        if exc_cls is SessionExpiredError or exc_cls is SessionRevokedError:
            raise exc_cls(uuid.uuid4())
        raise exc_cls()

    monkeypatch.setattr(deps, "validate_session", _raise)

    with pytest.raises(HTTPException) as excinfo:
        await get_current_actor(authorization="Bearer some-token")

    reference = unauthorized()
    assert excinfo.value.status_code == reference.status_code == 401
    assert excinfo.value.detail == reference.detail
