"""P2.3 -- proves, against a real Redis instance (the actual rate-limit
backend, not a fake), that an attacker cannot spoof their rate-limit
identity via `X-Forwarded-For`: two requests carrying different forged
prefixes but the same real (trusted) last hop share one bucket, while a
genuinely different last hop gets an independent one.

Marked `integration`. Run locally:

    docker compose up -d redis
    REDIS_URL=redis://localhost:6379/0 \\
        pytest -m integration tests/api/auth/test_proxy_trust_integration.py
"""

from __future__ import annotations

import os
import uuid
from unittest.mock import MagicMock

import pytest
from api.auth.config import AuthHttpConfig
from api.auth.routes import _enforce_auth_rate_limit
from fastapi import HTTPException
from infra.ratelimit.config import get_ratelimit_config

pytestmark = [pytest.mark.integration, pytest.mark.anyio]

_REDIS_URL = os.environ.get("REDIS_URL", "redis://localhost:6379/0")


@pytest.fixture(autouse=True)
def _require_reachable_redis(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("REDIS_URL", _REDIS_URL)
    monkeypatch.setenv("RATE_LIMIT_REQUESTS_PER_WINDOW", "2")
    monkeypatch.setenv("RATE_LIMIT_WINDOW_SECONDS", "60")
    get_ratelimit_config.cache_clear()
    try:
        import redis as redis_sync

        redis_sync.Redis.from_url(_REDIS_URL).ping()
    except Exception as exc:  # noqa: BLE001
        pytest.skip(f"REDIS_URL not configured for the integration test: {exc}")
    yield
    get_ratelimit_config.cache_clear()


def _fake_public_address() -> str:
    """A random-looking, never-reused address string -- there is no
    configurable key prefix in `infra.ratelimit`, so uniqueness across
    test runs (including a shared development Redis) comes from
    randomizing the address itself; the 60s window TTL cleans it up."""
    return f"198.51.100.{uuid.uuid4().int % 256}-{uuid.uuid4().hex[:6]}"


def _request(client_host: str, forwarded_for: str) -> MagicMock:
    request = MagicMock()
    request.client = MagicMock(host=client_host)
    request.headers = {"X-Forwarded-For": forwarded_for}
    return request


_TRUSTED = AuthHttpConfig(
    redirect_uri="https://app.example.com/auth/callback", trust_proxy_headers=True
)


async def test_spoofed_forwarded_prefixes_share_the_real_hops_bucket() -> None:
    """window = 2 requests. Three calls, three DIFFERENT attacker-forged
    prefixes, but the SAME real last hop (the trusted proxy's own
    observed peer) -- the third must still be rate-limited, proving the
    forged prefixes never created three separate identities."""
    real_hop = _fake_public_address()
    await _enforce_auth_rate_limit(_request("10.0.0.5", f"1.1.1.1, {real_hop}"), config=_TRUSTED)
    await _enforce_auth_rate_limit(_request("10.0.0.5", f"2.2.2.2, {real_hop}"), config=_TRUSTED)
    with pytest.raises(HTTPException) as excinfo:
        await _enforce_auth_rate_limit(
            _request("10.0.0.5", f"3.3.3.3, {real_hop}"), config=_TRUSTED
        )
    assert excinfo.value.status_code == 429


async def test_a_genuinely_different_last_hop_gets_an_independent_bucket() -> None:
    hop_a = _fake_public_address()
    hop_b = _fake_public_address()

    # Exhaust hop_a's window (2 requests).
    await _enforce_auth_rate_limit(_request("10.0.0.5", f"1.1.1.1, {hop_a}"), config=_TRUSTED)
    await _enforce_auth_rate_limit(_request("10.0.0.5", f"1.1.1.1, {hop_a}"), config=_TRUSTED)
    with pytest.raises(HTTPException):
        await _enforce_auth_rate_limit(_request("10.0.0.5", f"1.1.1.1, {hop_a}"), config=_TRUSTED)

    # hop_b is untouched -- a fresh window, not blocked by hop_a's exhaustion.
    await _enforce_auth_rate_limit(_request("10.0.0.5", f"9.9.9.9, {hop_b}"), config=_TRUSTED)
