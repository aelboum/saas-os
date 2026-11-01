"""Owner decision D of 2026-11-01: how the outbox dispatcher classifies a
consumer failure, without a database.

- An explicit `AmbiguousOutcomeError` keeps its own policy.
- A bare timeout that escapes a consumer unclassified -- `TimeoutError`
  (which `asyncio.TimeoutError`, `socket.timeout` and
  `concurrent.futures.TimeoutError` are), any subclass, an `httpx` timeout,
  or an exception group holding one -- is ambiguous with no retry policy:
  recorded through `record_ambiguous_outcome()` (dead-lettered,
  `OutcomeUnknown: <type> (unclassified)`), never through the ordinary retry.
- `ConfirmedNotSentError` is the explicit, typed "not sent": it keeps the
  ordinary retry even when it is also a `TimeoutError`.
- `PermanentEventError` and `RetryAfterEventError` keep their meaning.
- Any other exception keeps today's ordinary retry (the broader question is
  an open owner decision, docs/CONSUMER-GUIDE.md section 10).

The state-machine writes are replaced by recorders here; the integration
tests (`test_outbox_ambiguous_outcome_integration.py`) run the same paths
against PostgreSQL and Redis.
"""

from __future__ import annotations

import asyncio
import concurrent.futures
import socket
import uuid
from dataclasses import dataclass, field
from typing import Any

import httpx
import pytest

import saas_os.api.outbox_dispatcher as outbox_dispatcher
from saas_os.core.notifications.errors import (
    NotificationDispatchError,
    NotificationNotSentDispatchError,
)
from saas_os.core.outbox import (
    AmbiguousOutcomeError,
    ConfirmedNotSentError,
    PermanentEventError,
    RetryAfterEventError,
)
from saas_os.core.webhooks.errors import (
    WebhookDeliveryError,
    WebhookDestinationUnresolvedError,
    WebhookNotSentError,
)
from saas_os.infra.jobs import TenantJobContext, TenantJobPayload

pytestmark = pytest.mark.anyio

_TENANT = uuid.UUID("00000000-0000-4000-8000-000000000001")
_EVENT = uuid.UUID("00000000-0000-4000-8000-000000000002")
_TOKEN = uuid.UUID("00000000-0000-4000-8000-000000000003")


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


@dataclass
class _Recorder:
    """What the dispatcher asked the state machine to record."""

    calls: list[tuple[str, Any, dict[str, Any]]] = field(default_factory=list)

    def fail_event(
        self, tenant_id: uuid.UUID, event_id: uuid.UUID, token: uuid.UUID, error: Any, **kwargs: Any
    ) -> str:
        self.calls.append(("fail_event", error, kwargs))
        return "pending"

    def record_ambiguous(
        self, tenant_id: uuid.UUID, event_id: uuid.UUID, token: uuid.UUID, error: Any
    ) -> str:
        self.calls.append(("ambiguous", error, {}))
        return "dead_lettered"

    @property
    def only(self) -> tuple[str, Any, dict[str, Any]]:
        (call,) = self.calls
        return call


@pytest.fixture
def recorder(monkeypatch: pytest.MonkeyPatch) -> _Recorder:
    rec = _Recorder()
    monkeypatch.setattr(outbox_dispatcher, "fail_event", rec.fail_event)
    monkeypatch.setattr(outbox_dispatcher, "record_ambiguous_outcome", rec.record_ambiguous)
    return rec


def _record(exc: Exception) -> None:
    outbox_dispatcher._record_consumer_failure(  # pyright: ignore[reportPrivateUsage]
        TenantJobContext(tenant_id=_TENANT), _EVENT, _TOKEN, exc, {}
    )


def _request() -> httpx.Request:
    return httpx.Request("POST", "https://receiver.example/hook")


class _ClientTimeout(TimeoutError):
    """A product client's own timeout class."""


_CANARY = "https://canary.example/secret-path"

_BARE_TIMEOUTS: list[Exception] = [
    TimeoutError(_CANARY),
    asyncio.TimeoutError(_CANARY),  # noqa: UP041 -- the alias is the point
    socket.timeout(_CANARY),  # noqa: UP041 -- the alias is the point
    concurrent.futures.TimeoutError(_CANARY),
    _ClientTimeout(_CANARY),
    httpx.ReadTimeout(_CANARY, request=_request()),
    httpx.WriteTimeout(_CANARY, request=_request()),
    httpx.ConnectTimeout(_CANARY, request=_request()),
    httpx.PoolTimeout(_CANARY, request=_request()),
    ExceptionGroup(_CANARY, [ValueError("x"), TimeoutError(_CANARY)]),
    ExceptionGroup(_CANARY, [ExceptionGroup("inner", [httpx.ReadTimeout(_CANARY)])]),
]


@pytest.mark.parametrize("exc", _BARE_TIMEOUTS, ids=lambda e: type(e).__name__)
def test_a_bare_timeout_is_ambiguous_without_a_retry_policy(
    recorder: _Recorder, exc: Exception
) -> None:
    _record(exc)
    kind, error, _ = recorder.only
    assert kind == "ambiguous"
    assert isinstance(error, AmbiguousOutcomeError)
    assert (error.reason, error.phase) == (type(exc).__name__, "unclassified")
    assert error.retry_within is None and error.at_least_once is False
    # Only the type name is kept: a timeout's text may carry a URL.
    assert _CANARY not in f"{error!s} {error!r} {vars(error)!r}"


def _wrapped_timeout() -> RuntimeError:
    """A timeout the consumer caught and re-raised as its own error: that is
    its classification (only the raised exception's type is inspected)."""
    try:
        try:
            raise TimeoutError("inner")
        except TimeoutError as inner:
            raise RuntimeError("wrapped") from inner
    except RuntimeError as outer:
        return outer


class _NotSentTimeout(ConfirmedNotSentError, TimeoutError):
    """A consumer's connect timeout, classified explicitly as not sent."""


@pytest.mark.parametrize(
    "exc",
    [
        _NotSentTimeout("connect timeout"),
        ConfirmedNotSentError("connection refused"),
        WebhookNotSentError(_EVENT, "ConnectTimeout"),
        WebhookDestinationUnresolvedError("https://receiver.example/hook"),
        NotificationNotSentDispatchError(_EVENT, "EmailNotSentError"),
    ],
    ids=lambda e: type(e).__name__,
)
def test_an_explicit_not_sent_keeps_the_ordinary_retry(recorder: _Recorder, exc: Exception) -> None:
    _record(exc)
    kind, error, kwargs = recorder.only
    assert (kind, error, kwargs) == ("fail_event", exc, {})


@pytest.mark.parametrize(
    "exc",
    [
        RuntimeError("boom"),
        ValueError("bad"),
        WebhookDeliveryError(_EVENT, "HTTP 503"),
        NotificationDispatchError(_EVENT, "EmailProviderError"),
        ExceptionGroup("no timeout inside", [ValueError("x")]),
        _wrapped_timeout(),
    ],
    ids=lambda e: type(e).__name__,
)
def test_any_other_exception_keeps_the_ordinary_retry(recorder: _Recorder, exc: Exception) -> None:
    _record(exc)
    assert recorder.only == ("fail_event", exc, {})


def test_an_explicit_ambiguous_outcome_keeps_its_own_policy(recorder: _Recorder) -> None:
    class _AmbiguousTimeout(AmbiguousOutcomeError, TimeoutError):
        pass

    exc = _AmbiguousTimeout("read_timeout", phase="read", at_least_once=True)
    _record(exc)
    assert recorder.only == ("ambiguous", exc, {})


def test_permanent_and_retry_after_keep_their_meaning_on_a_timeout(recorder: _Recorder) -> None:
    class _PermanentTimeout(PermanentEventError, TimeoutError):
        pass

    class _DeferredTimeout(RetryAfterEventError, TimeoutError):
        pass

    permanent = _PermanentTimeout("refused")
    deferred = _DeferredTimeout(30.0, "rate_limited")
    _record(permanent)
    _record(deferred)
    assert recorder.calls == [
        ("fail_event", permanent, {"terminal": True}),
        ("fail_event", deferred, {"retry_after": 30.0}),
    ]


def test_an_error_cannot_be_both_ambiguous_and_confirmed_not_sent() -> None:
    with pytest.raises(TypeError):

        class _Both(AmbiguousOutcomeError, ConfirmedNotSentError):  # pyright: ignore[reportUnusedClass]
            pass

    with pytest.raises(TypeError):

        class _Both2(ConfirmedNotSentError, AmbiguousOutcomeError):  # pyright: ignore[reportUnusedClass]
            pass


# --- Through `_run_outbox_event` (the except clauses' order) ---------------


@dataclass
class _Execution:
    id: uuid.UUID = _EVENT
    tenant_id: uuid.UUID = _TENANT
    event_type: str = "test.d"
    correlation_id: str | None = None
    payload: dict[str, object] = field(default_factory=dict)


async def _run(monkeypatch: pytest.MonkeyPatch, error: BaseException) -> None:
    async def consumer(_ctx: TenantJobContext, _payload: TenantJobPayload) -> None:
        raise error

    completed: list[int] = []
    monkeypatch.setattr(outbox_dispatcher, "begin_event_execution", lambda *a, **k: _Execution())
    monkeypatch.setattr(outbox_dispatcher, "complete_event", lambda *a, **k: completed.append(1))
    monkeypatch.setattr(outbox_dispatcher, "outbox_event_handlers", lambda: {"test.d": consumer})
    await outbox_dispatcher._run_outbox_event(  # pyright: ignore[reportPrivateUsage]
        TenantJobContext(tenant_id=_TENANT),
        TenantJobPayload(
            tenant_id=str(_TENANT),
            data={"outbox_event_id": str(_EVENT), "claim_token": str(_TOKEN)},
        ),
    )
    assert completed == []  # never published


async def test_a_consumer_timeout_through_the_job_is_dead_lettered_as_unknown(
    monkeypatch: pytest.MonkeyPatch, recorder: _Recorder
) -> None:
    await _run(monkeypatch, TimeoutError("client read timeout"))
    kind, error, _ = recorder.only
    assert kind == "ambiguous" and error.phase == "unclassified"


async def test_an_httpx_timeout_through_the_job_is_dead_lettered_as_unknown(
    monkeypatch: pytest.MonkeyPatch, recorder: _Recorder
) -> None:
    await _run(monkeypatch, httpx.ReadTimeout("read"))
    kind, error, _ = recorder.only
    assert (kind, error.reason) == ("ambiguous", "ReadTimeout")


async def test_a_not_sent_timeout_through_the_job_is_retried(
    monkeypatch: pytest.MonkeyPatch, recorder: _Recorder
) -> None:
    exc = _NotSentTimeout("connect timeout")
    await _run(monkeypatch, exc)
    assert recorder.only == ("fail_event", exc, {})


async def test_the_dispatchers_own_deadline_is_still_consumer_timed_out(
    monkeypatch: pytest.MonkeyPatch, recorder: _Recorder
) -> None:
    async def hangs(_ctx: TenantJobContext, _payload: TenantJobPayload) -> None:
        await asyncio.sleep(5)

    monkeypatch.setattr(outbox_dispatcher, "OUTBOX_CONSUMER_TIMEOUT_SECONDS", 0.05)
    monkeypatch.setattr(outbox_dispatcher, "begin_event_execution", lambda *a, **k: _Execution())
    monkeypatch.setattr(outbox_dispatcher, "outbox_event_handlers", lambda: {"test.d": hangs})
    await outbox_dispatcher._run_outbox_event(  # pyright: ignore[reportPrivateUsage]
        TenantJobContext(tenant_id=_TENANT),
        TenantJobPayload(
            tenant_id=str(_TENANT),
            data={"outbox_event_id": str(_EVENT), "claim_token": str(_TOKEN)},
        ),
    )
    kind, error, kwargs = recorder.only
    assert kind == "fail_event" and kwargs == {"terminal": True}
    assert str(error).startswith("ConsumerTimedOut:")
