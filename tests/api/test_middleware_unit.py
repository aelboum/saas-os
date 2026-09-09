"""Unit tests for `api.middleware.CorrelationIdMiddleware`
(docs/IMPLEMENTATION-ROADMAP.md P1.4: wiring `infra/observability`'s
existing correlation/logging/tracing foundation into the API request
lifecycle).

A tiny, dedicated Starlette test app (not `api.main.app`) is used here so
these tests need no database/Redis and can exercise the middleware's own
contract in isolation -- concurrency, context cleanup, error paths, and
logging safety. `tests/api/v1/test_correlation_integration.py` covers the
same header end-to-end through the real authenticated middleware chain.
"""

from __future__ import annotations

import asyncio
import logging

import pytest
from api.middleware import CORRELATION_ID_HEADER, CorrelationIdMiddleware
from httpx import ASGITransport, AsyncClient
from infra.observability.context import get_correlation_context
from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


async def _echo(request):  # noqa: ANN001
    delay = float(request.query_params.get("delay", "0"))
    if delay:
        await asyncio.sleep(delay)
    ctx = get_correlation_context()
    return JSONResponse({"request_id": ctx.request_id, "tenant_id": ctx.tenant_id})


async def _raise_http(request):  # noqa: ANN001
    status_code = int(request.path_params["status_code"])
    raise HTTPException(status_code=status_code, detail="denied")


async def _boom(request):  # noqa: ANN001
    raise RuntimeError("internal detail that must never reach the response body")


async def _context_probe(request):  # noqa: ANN001
    # Proves context is bound *before* the handler runs, without needing
    # the real auth chain -- api/dependencies.py is what actually
    # populates tenant_id/user_id downstream in the real app; this
    # confirms the middleware itself never sets them.
    ctx = get_correlation_context()
    return JSONResponse({"tenant_id": ctx.tenant_id, "user_id": ctx.user_id})


def _build_app() -> Starlette:
    app = Starlette(
        routes=[
            Route("/echo", _echo),
            Route("/status/{status_code}", _raise_http),
            Route("/boom", _boom),
            Route("/probe", _context_probe),
        ]
    )
    app.add_middleware(CorrelationIdMiddleware)
    return app


@pytest.fixture
def app() -> Starlette:
    return _build_app()


@pytest.fixture
def client(app: Starlette) -> TestClient:
    return TestClient(app, raise_server_exceptions=False)


# --- Correlation: generated / accepted / header --------------------------


def test_generates_an_id_when_none_is_supplied(client: TestClient) -> None:
    response = client.get("/echo")
    request_id = response.headers.get(CORRELATION_ID_HEADER)
    assert request_id
    assert response.json()["request_id"] == request_id


def test_accepts_a_well_formed_incoming_id(client: TestClient) -> None:
    response = client.get("/echo", headers={CORRELATION_ID_HEADER: "caller-supplied-id-123"})
    assert response.headers[CORRELATION_ID_HEADER] == "caller-supplied-id-123"
    assert response.json()["request_id"] == "caller-supplied-id-123"


@pytest.mark.parametrize(
    "malformed",
    [
        "has a space",
        "has\nnewline",
        "has;semicolon",
        "a" * 200,  # too long
        "",
    ],
)
async def test_rejects_a_malformed_incoming_id_and_generates_one_instead(
    malformed: str,
) -> None:
    app = _build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/echo", headers={CORRELATION_ID_HEADER: malformed})
    returned = response.headers.get(CORRELATION_ID_HEADER)
    assert returned
    assert returned != malformed


def test_two_sequential_requests_get_different_generated_ids(client: TestClient) -> None:
    first = client.get("/echo").headers[CORRELATION_ID_HEADER]
    second = client.get("/echo").headers[CORRELATION_ID_HEADER]
    assert first != second


# --- Context lifecycle: cleanup / no leakage between requests ------------


def test_context_is_empty_outside_any_request(client: TestClient) -> None:
    assert get_correlation_context().request_id is None
    client.get("/echo")
    # Restored after the request completes -- no leakage into subsequent,
    # unrelated code running on the same thread/task.
    assert get_correlation_context().request_id is None


def test_middleware_never_sets_tenant_or_user_context(client: TestClient) -> None:
    """Security boundary: this middleware runs before authentication/
    tenant resolution and must never itself populate tenant_id/user_id --
    those come only from api/dependencies.py's own verified chain."""
    response = client.get("/probe", headers={CORRELATION_ID_HEADER: "attacker-supplied"})
    body = response.json()
    assert body["tenant_id"] is None
    assert body["user_id"] is None


# --- Concurrency: real async concurrency, not sequential requests --------


async def test_concurrent_requests_do_not_inherit_each_others_context() -> None:
    """The literal P1.4 requirement: two requests running *actually
    concurrently* (not one after another) must never see each other's
    request_id. The first request sleeps mid-handler so the second
    request's context bind genuinely overlaps with it in wall-clock time.
    """
    app = _build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        slow_call = client.get(
            "/echo", params={"delay": "0.2"}, headers={CORRELATION_ID_HEADER: "slow-request"}
        )
        fast_call = client.get(
            "/echo", params={"delay": "0"}, headers={CORRELATION_ID_HEADER: "fast-request"}
        )
        slow_response, fast_response = await asyncio.gather(slow_call, fast_call)

    assert slow_response.json()["request_id"] == "slow-request"
    assert fast_response.json()["request_id"] == "fast-request"
    assert slow_response.headers[CORRELATION_ID_HEADER] == "slow-request"
    assert fast_response.headers[CORRELATION_ID_HEADER] == "fast-request"


async def test_many_concurrent_requests_each_keep_their_own_id() -> None:
    app = _build_app()
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        ids = [f"req-{i}" for i in range(20)]
        calls = [
            client.get("/echo", params={"delay": "0.05"}, headers={CORRELATION_ID_HEADER: rid})
            for rid in ids
        ]
        responses = await asyncio.gather(*calls)

    returned_ids = [r.json()["request_id"] for r in responses]
    assert returned_ids == ids  # each response paired with its own request's id
    assert len(set(returned_ids)) == len(ids)  # no duplicates/collisions


# --- Error paths: header survives every status class ----------------------


@pytest.mark.parametrize("status_code", [401, 403, 404, 429, 400])
def test_header_present_on_every_http_exception_status(
    client: TestClient, status_code: int
) -> None:
    response = client.get(f"/status/{status_code}")
    assert response.status_code == status_code
    assert response.headers.get(CORRELATION_ID_HEADER)


def test_header_present_and_no_leak_on_unhandled_exception(client: TestClient) -> None:
    response = client.get("/boom")
    assert response.status_code == 500
    assert response.headers.get(CORRELATION_ID_HEADER)
    assert "internal detail" not in response.text
    assert "Traceback" not in response.text
    assert response.text == "Internal Server Error"


def test_header_present_on_successful_response(client: TestClient) -> None:
    response = client.get("/echo")
    assert response.status_code == 200
    assert response.headers.get(CORRELATION_ID_HEADER)


# --- Logging: correlation id visible downstream, no secrets ---------------


def test_correlation_id_is_attached_to_log_records_during_the_request(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    from infra.observability.config import ObservabilityConfig
    from infra.observability.logging import CorrelationFilter

    caplog.set_level(logging.INFO)
    handler_filter = CorrelationFilter(ObservabilityConfig())
    caplog.handler.addFilter(handler_filter)
    try:
        response = client.get("/echo", headers={CORRELATION_ID_HEADER: "log-visible-id"})
    finally:
        caplog.handler.removeFilter(handler_filter)

    assert response.status_code == 200
    matching = [r for r in caplog.records if getattr(r, "request_id", None) == "log-visible-id"]
    assert matching, "expected at least one log record carrying the request's correlation id"


def test_emitted_request_metadata_never_contains_the_authorization_header(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO)
    secret_token = (
        "Bearer super-secret-session-token-value"  # pragma: allowlist secret  # noqa: S105
    )
    client.get("/echo", headers={"Authorization": secret_token})

    for record in caplog.records:
        message = record.getMessage()
        assert secret_token not in message
        assert "super-secret-session-token-value" not in message
        for value in vars(record).values():
            assert "super-secret-session-token-value" not in str(value)


def test_access_log_line_only_contains_safe_metadata_fields(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.INFO)
    client.get("/echo?some=query&value=here")

    completed = [r for r in caplog.records if r.getMessage() == "request_completed"]
    assert completed
    record = completed[0]
    assert getattr(record, "http_method", None) == "GET"
    assert getattr(record, "http_path", None) == "/echo"  # path only, no query string
    assert getattr(record, "http_status_code", None) == 200
    assert isinstance(getattr(record, "duration_ms", None), float)
