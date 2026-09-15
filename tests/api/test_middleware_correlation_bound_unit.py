"""PRIV-03 Phase P11 (privacy re-audit RA-07, finding 1): the accepted
`X-Request-ID` length is exactly the audit log's `correlation_id` column
width (100). A 101- to 128-character header used to be accepted here and
then rejected by the database inside the audited authorization-denial
write. Same isolated Starlette app as `test_middleware_unit.py`; the
end-to-end proof through the real app is
`tests/api/v1/test_audit_correlation_id_bound_integration.py`.
"""

from __future__ import annotations

import uuid

import pytest
from api.middleware import CORRELATION_ID_HEADER, CorrelationIdMiddleware
from infra.observability.context import get_correlation_context
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

_LIMIT = 100


async def _echo(request):  # noqa: ANN001
    return JSONResponse({"request_id": get_correlation_context().request_id})


@pytest.fixture
def client() -> TestClient:
    app = Starlette(routes=[Route("/echo", _echo)])
    app.add_middleware(CorrelationIdMiddleware)
    return TestClient(app, raise_server_exceptions=False)


def test_an_id_exactly_at_the_audit_column_width_is_accepted(client: TestClient) -> None:
    supplied = "a" * _LIMIT
    response = client.get("/echo", headers={CORRELATION_ID_HEADER: supplied})
    assert response.headers[CORRELATION_ID_HEADER] == supplied
    assert response.json()["request_id"] == supplied


@pytest.mark.parametrize("length", [_LIMIT + 1, 128])
def test_an_id_longer_than_the_audit_column_width_is_replaced_by_a_generated_one(
    length: int, client: TestClient
) -> None:
    """Treated exactly like a malformed header: absent, so a fresh uuid4 is
    bound and echoed -- never the caller's value, and never anything the
    audit write could fail to store."""
    supplied = "b" * length
    response = client.get("/echo", headers={CORRELATION_ID_HEADER: supplied})
    returned = response.headers[CORRELATION_ID_HEADER]
    assert returned != supplied
    assert len(returned) <= _LIMIT
    assert uuid.UUID(returned).version == 4
    assert response.json()["request_id"] == returned


def test_character_restrictions_are_unchanged_by_the_new_length_bound(client: TestClient) -> None:
    for malformed in ("has space", "has\nnewline", "x" * 50 + ";" + "x" * 49, ""):
        response = client.get("/echo", headers={CORRELATION_ID_HEADER: malformed})
        assert response.headers[CORRELATION_ID_HEADER] != malformed
    accepted = "A-z.0_9" * 10  # 70 chars, every allowed class
    response = client.get("/echo", headers={CORRELATION_ID_HEADER: accepted})
    assert response.headers[CORRELATION_ID_HEADER] == accepted
