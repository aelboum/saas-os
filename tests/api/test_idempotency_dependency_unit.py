"""P1.11 -- unit tests for `api.dependencies.get_idempotency_key()`'s
header-validation/mapping. No database needed -- this dependency makes
no database call itself (it only parses and validates a header value).
"""

from __future__ import annotations

import api.dependencies as deps
import pytest
from fastapi import HTTPException

pytestmark = pytest.mark.anyio


async def test_missing_header_returns_none() -> None:
    result = await deps.get_idempotency_key(idempotency_key=None)
    assert result is None


async def test_valid_header_is_returned_unchanged() -> None:
    result = await deps.get_idempotency_key(idempotency_key="order-2026-09-09-abc123")
    assert result == "order-2026-09-09-abc123"


async def test_empty_header_is_rejected() -> None:
    with pytest.raises(HTTPException) as excinfo:
        await deps.get_idempotency_key(idempotency_key="")
    assert excinfo.value.status_code == 400
    assert excinfo.value.detail == "Invalid Idempotency-Key."


async def test_oversized_header_is_rejected() -> None:
    with pytest.raises(HTTPException) as excinfo:
        await deps.get_idempotency_key(idempotency_key="a" * 201)
    assert excinfo.value.status_code == 400


async def test_malformed_header_is_rejected() -> None:
    with pytest.raises(HTTPException) as excinfo:
        await deps.get_idempotency_key(idempotency_key="has spaces/and;bad chars")
    assert excinfo.value.status_code == 400


async def test_error_never_echoes_the_offending_value() -> None:
    malformed = "has spaces/and;bad chars"
    with pytest.raises(HTTPException) as excinfo:
        await deps.get_idempotency_key(idempotency_key=malformed)
    assert malformed not in str(excinfo.value.detail)
