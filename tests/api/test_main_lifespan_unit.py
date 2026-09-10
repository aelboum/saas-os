"""Unit tests for the P1.2 startup-guard wiring -- no real database
needed. `infra.db.get_engine`/`validate_application_role` are monkeypatched
in `api.platform`'s own namespace (the module that now owns `lifespan`,
docs/ADR/0017 -- `build_platform_app()` moved this out of `api.main` in
the SaaS OS packaging/consumer implementation phase), so these tests
exercise only the FastAPI `lifespan` wiring itself (does an unsafe role
actually prevent the application from becoming ready?), not real
PostgreSQL role semantics -- `tests/infra/db/test_role_guard_integration.py`
covers that separately, against a real database. Exercised through
`api.main.create_app()` -- this repository's own consumer of
`build_platform_app()` -- so this also proves the guard survives that
composition.
"""

from __future__ import annotations

import api.main as main_module
import api.platform as platform_module
import pytest
from fastapi.testclient import TestClient
from infra.db.role_guard import ApplicationRoleValidation, UnsafeDatabaseRoleError

pytestmark = pytest.mark.anyio


def _stub_unsafe(*, message: str = "superuser role rejected"):
    def _raise(engine: object) -> ApplicationRoleValidation:
        raise UnsafeDatabaseRoleError(message)

    return _raise


def _stub_safe(role_name: str = "safe_role"):
    def _pass(engine: object) -> ApplicationRoleValidation:
        return ApplicationRoleValidation(role_name=role_name)

    return _pass


async def test_lifespan_allows_startup_when_role_is_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(platform_module, "get_engine", lambda: object())
    monkeypatch.setattr(platform_module, "validate_application_role", _stub_safe())

    app = main_module.create_app()
    async with app.router.lifespan_context(app):
        pass  # startup completed without raising


async def test_lifespan_fails_startup_when_role_is_unsafe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(platform_module, "get_engine", lambda: object())
    monkeypatch.setattr(platform_module, "validate_application_role", _stub_unsafe())

    app = main_module.create_app()
    with pytest.raises(UnsafeDatabaseRoleError):
        async with app.router.lifespan_context(app):
            pass  # pragma: no cover -- startup must raise before this runs


def test_testclient_startup_fails_when_role_is_unsafe(monkeypatch: pytest.MonkeyPatch) -> None:
    """The critical end-to-end property at the ASGI boundary: entering
    `TestClient(app)` as a context manager is what actually triggers the
    ASGI `lifespan` startup phase (the same phase a real ASGI server runs
    before accepting traffic) -- an unsafe role must prevent the
    application from becoming ready via this real path, not merely raise
    somewhere deep inside a function nobody calls at startup."""
    monkeypatch.setattr(platform_module, "get_engine", lambda: object())
    monkeypatch.setattr(platform_module, "validate_application_role", _stub_unsafe())

    app = main_module.create_app()
    with pytest.raises(UnsafeDatabaseRoleError):
        with TestClient(app):
            pass  # pragma: no cover -- startup must raise before this runs


def test_testclient_starts_normally_when_role_is_safe(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(platform_module, "get_engine", lambda: object())
    monkeypatch.setattr(platform_module, "validate_application_role", _stub_safe())

    app = main_module.create_app()
    with TestClient(app) as client:
        assert client is not None  # startup completed; the app became ready


def test_no_configuration_flag_disables_the_startup_guard() -> None:
    """`build_platform_app()` unconditionally wires `lifespan` -- there is
    no parameter, environment variable, or feature flag anywhere in that
    function (or in `api.main.create_app()`, which never touches
    `lifespan` itself) that could skip the guard."""
    import inspect

    platform_source = inspect.getsource(platform_module.build_platform_app)
    assert "lifespan=_platform_lifespan" in platform_source

    create_app_source = inspect.getsource(main_module.create_app)
    assert "lifespan" not in create_app_source  # delegated entirely to build_platform_app()
