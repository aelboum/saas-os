"""An invalid `AI_EGRESS_*` setting surfaces from `run_inference` as a typed
`InferenceInternalError`, never as the egress layer's own
`EgressConfigurationError` (the public interface raises only the
`InferenceError` family).

The total deadline is the first thing `run_inference` computes, before the
tenant check, authorization, admission or any audit row, so a misconfigured
deployment fails there: nothing is read, authorized, recorded or sent, and
the refusal is not attributed to the caller. No database is needed.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from saas_os.control_plane.inference import service
from saas_os.control_plane.inference.adapters.fake import FakeAdapter
from saas_os.control_plane.inference.errors import InferenceError, InferenceInternalError
from saas_os.control_plane.inference.types import ContentPart, InferenceRequest, Message
from saas_os.core.authority import UserCaller
from saas_os.infra.egress import EgressConfigurationError

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


class _NeverAdmitted:
    async def admit(self, tenant_id: uuid.UUID, *, ttl_seconds: float) -> object:
        raise AssertionError("admission must not be reached")

    async def release(self, slot: object) -> None:
        raise AssertionError("admission must not be reached")


def _request() -> InferenceRequest:
    return InferenceRequest(
        alias="default-chat",
        use_case="audit.deadline",
        messages=(Message("user", (ContentPart("text", "none", text="hello"),)),),
        max_output_tokens=16,
    )


@pytest.fixture
def untouched(monkeypatch: pytest.MonkeyPatch) -> dict[str, list[Any]]:
    """Fail the test if anything after the deadline is reached: the tenant
    check, authorization, an audit row or a denial row."""
    reached: dict[str, list[Any]] = {"calls": []}

    def _fail(name: str):
        def _called(*args: object, **kwargs: object) -> None:
            reached["calls"].append(name)
            raise AssertionError(f"{name} must not be reached")

        return _called

    for name in ("require_open_tenant", "_authorize_in_tenant", "record", "_record_denied"):
        monkeypatch.setattr(service, name, _fail(name))
    return reached


@pytest.mark.parametrize(
    ("variable", "value"),
    [
        ("AI_EGRESS_TOTAL_DEADLINE_SECONDS", "0"),
        ("AI_EGRESS_TOTAL_DEADLINE_SECONDS", "not-a-number"),
        ("AI_EGRESS_TOTAL_DEADLINE_SECONDS", "inf"),
        # All four settings are parsed together, so any of them fails here.
        ("AI_EGRESS_CONNECT_TIMEOUT_SECONDS", "-1"),
        ("AI_EGRESS_MAX_RESPONSE_BYTES", "1.5"),
    ],
)
async def test_an_invalid_egress_setting_is_a_typed_internal_error(
    monkeypatch: pytest.MonkeyPatch,
    untouched: dict[str, list[Any]],
    variable: str,
    value: str,
) -> None:
    monkeypatch.setenv(variable, value)
    fake = FakeAdapter()
    runtime = service.InferenceRuntime(adapters={"fake": fake}, admission=_NeverAdmitted())

    with pytest.raises(InferenceError) as caught:
        await service.run_inference(
            UserCaller(uuid.uuid4()), tenant_id=uuid.uuid4(), request=_request(), runtime=runtime
        )

    error = caught.value
    assert type(error) is InferenceInternalError
    assert error.category == "internal"
    assert error.reason == f"invalid_{variable.lower()}"
    assert isinstance(error.__cause__, EgressConfigurationError)
    assert not isinstance(error, EgressConfigurationError)
    assert fake.calls == []
    assert untouched["calls"] == []


async def test_a_runtime_deadline_does_not_read_the_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The internal runtime seam keeps its existing precedence: an explicit
    `total_deadline_seconds` is used as is, without parsing the settings."""
    monkeypatch.setenv("AI_EGRESS_TOTAL_DEADLINE_SECONDS", "0")
    runtime = service.InferenceRuntime(adapters={}, total_deadline_seconds=30.0)
    assert service._total_deadline(_request(), runtime) == 30.0


def test_a_valid_setting_is_still_used(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AI_EGRESS_TOTAL_DEADLINE_SECONDS", "45")
    runtime = service.InferenceRuntime(adapters={})
    assert service._total_deadline(_request(), runtime) == 45.0
