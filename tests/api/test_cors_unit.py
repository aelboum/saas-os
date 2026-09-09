"""P2.3 -- CORS: the production topology serves frontend and backend from
one origin behind the proxy, so no `CORSMiddleware` is installed at all
(`docs/DEPLOYMENT-ARCHITECTURE.md` §11). This is a structural proof, not a
configuration test: there is no allowlist to misconfigure because no CORS
middleware exists in the ASGI stack -- an unknown origin gets exactly the
same response (no `Access-Control-Allow-Origin` header) as any other
origin, and a wildcard-plus-credentials configuration is impossible
because there is no configuration surface for it.
"""

from __future__ import annotations

from api.main import app
from fastapi.testclient import TestClient


def test_no_cors_middleware_is_installed() -> None:
    from starlette.middleware.cors import CORSMiddleware

    assert not any(getattr(m, "cls", None) is CORSMiddleware for m in app.user_middleware)


def test_no_origin_ever_receives_an_access_control_allow_origin_header() -> None:
    client = TestClient(app)
    for origin in ("https://allowed.example.com", "https://attacker.example.com", None):
        headers = {"Origin": origin} if origin else {}
        response = client.get("/healthz", headers=headers)
        assert "access-control-allow-origin" not in {k.lower() for k in response.headers}


def test_preflight_request_gets_no_cors_headers_either() -> None:
    client = TestClient(app)
    response = client.options(
        "/healthz",
        headers={
            "Origin": "https://attacker.example.com",
            "Access-Control-Request-Method": "GET",
        },
    )
    assert "access-control-allow-origin" not in {k.lower() for k in response.headers}
    assert "access-control-allow-credentials" not in {k.lower() for k in response.headers}
