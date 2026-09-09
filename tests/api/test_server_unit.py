"""Unit tests for `api/server.py`, the P1.8 production ASGI entrypoint --
no real Uvicorn server is started here (that is
`tests/api/test_runtime_integration.py`'s job); this file only proves the
wiring: the real `api.main.app` object is passed through unchanged, and
`core.config.get_settings()`'s host/port/log-level are threaded into
`uvicorn.run()` without a second configuration mechanism being invented.
"""

from __future__ import annotations

import api.server as server_module
import pytest
from core.config import Settings


def test_main_calls_uvicorn_run_with_the_real_app_and_settings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def _fake_run(app: object, **kwargs: object) -> None:
        captured["app"] = app
        captured.update(kwargs)

    monkeypatch.setattr(server_module, "uvicorn", type("_U", (), {"run": staticmethod(_fake_run)}))
    monkeypatch.setattr(
        server_module,
        "get_settings",
        lambda: Settings(host="0.0.0.0", port=9001, log_level="WARNING"),
    )

    server_module.main()

    assert captured["app"] is server_module.app
    assert captured["host"] == "0.0.0.0"
    assert captured["port"] == 9001
    assert captured["log_level"] == "warning"


def test_no_second_fastapi_application_is_constructed() -> None:
    """`api/server.py` must import the one real `api.main.app` instance,
    never call `create_app()` itself or build a parallel application."""
    import inspect

    source = inspect.getsource(server_module.main)
    assert "create_app(" not in source
    assert server_module.app is server_module.__dict__["app"]

    module_source = inspect.getsource(server_module)
    assert "from api.main import app" in module_source
