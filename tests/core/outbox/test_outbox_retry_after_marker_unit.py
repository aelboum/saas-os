"""Retry after a started marker, database-free parts
(`docs/architecture/OUTBOX-RETRY-AFTER-MARKER-DESIGN.md`, sections 4, 5, 7, 13):

- `TenantJobContext.external_effect()` hands the exception object that left
  the block to `on_external_effect_failure`, class-agnostic, and only then;
- the attestation rule (`_is_attested_not_sent()`): every leaf a
  `ConfirmedNotSentError`, each one a leaf of the block's exception;
- the dispatcher's routing: only a marked attempt reaches the new branches;
  a marked `RetryAfterEventError` alone, a bare timeout, `retry_within` and
  every other failure keep the old path; markers off, nothing is reachable;
- the texts and logs carry no URL, recipient or payload.

The state-machine writes are replaced by recorders; the integration tests
(`test_outbox_retry_after_marker_integration.py`) run the same paths against
PostgreSQL.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

import pytest

import saas_os.api.outbox_dispatcher as outbox_dispatcher
import saas_os.core.outbox.dispatch as dispatch
from saas_os.core.outbox import (
    AmbiguousOutcomeError,
    ConfirmedNotSentError,
    PermanentEventError,
    RetryAfterEventError,
)
from saas_os.core.webhooks.errors import WebhookAmbiguousDeliveryError, WebhookNotSentError
from saas_os.infra.jobs import TenantJobContext

_TENANT = uuid.UUID("00000000-0000-4000-8000-000000000001")
_EVENT = uuid.UUID("00000000-0000-4000-8000-000000000002")
_TOKEN = uuid.UUID("00000000-0000-4000-8000-000000000003")
_CANARY = "https://canary.example/secret-path"


class _NotSent(ConfirmedNotSentError):
    pass


class _NotSentTimeout(ConfirmedNotSentError, TimeoutError):
    pass


class _NotSentRetryAfter(ConfirmedNotSentError, RetryAfterEventError):
    def __init__(self) -> None:
        RetryAfterEventError.__init__(self, 90, "Throttled")


class _NotSentPermanent(ConfirmedNotSentError, PermanentEventError):
    pass


def _amb(**kwargs: Any) -> AmbiguousOutcomeError:
    return AmbiguousOutcomeError("read_timeout", phase="read", **kwargs)


# --- The hook in the context manager -----------------------------------------------


def test_the_hook_receives_the_very_exception_that_left_the_block() -> None:
    seen: list[BaseException] = []
    context = TenantJobContext(tenant_id=uuid.uuid4(), on_external_effect_failure=seen.append)
    boom = _NotSent(_CANARY)

    with pytest.raises(_NotSent) as raised:
        with context.external_effect():
            raise boom

    assert raised.value is boom
    assert len(seen) == 1 and seen[0] is boom


def test_the_hook_is_not_called_when_the_block_exits_normally() -> None:
    seen: list[BaseException] = []
    context = TenantJobContext(tenant_id=uuid.uuid4(), on_external_effect_failure=seen.append)

    with context.external_effect():
        pass

    assert seen == []


def test_the_hook_is_class_agnostic_and_sees_every_exception() -> None:
    seen: list[BaseException] = []
    context = TenantJobContext(tenant_id=uuid.uuid4(), on_external_effect_failure=seen.append)
    errors: list[BaseException] = [RuntimeError("x"), KeyboardInterrupt(), _NotSent("y")]

    for error in errors:
        with pytest.raises(type(error)):
            with context.external_effect():
                raise error

    assert seen == errors


def test_an_error_raised_after_the_block_is_not_reported() -> None:
    """A consumer that catches the block's failure and raises a fresh
    attestation after it: the hook saw the block's own exception only."""
    seen: list[BaseException] = []
    context = TenantJobContext(tenant_id=uuid.uuid4(), on_external_effect_failure=seen.append)
    inside, fresh = RuntimeError("HTTP 503"), _NotSent("after")

    with pytest.raises(_NotSent):
        try:
            with context.external_effect():
                raise inside
        except RuntimeError:
            raise fresh from None

    assert seen == [inside]


def test_a_refused_marker_never_reaches_the_hook() -> None:
    seen: list[BaseException] = []

    def _refuse() -> None:
        raise RuntimeError("refused")

    context = TenantJobContext(
        tenant_id=uuid.uuid4(),
        start_external_effect=_refuse,
        on_external_effect_failure=seen.append,
    )
    with pytest.raises(RuntimeError):
        with context.external_effect():
            pytest.fail("the block must not run")

    assert seen == []


def test_without_a_hook_the_exception_propagates_unchanged() -> None:
    context = TenantJobContext(tenant_id=uuid.uuid4())
    boom = RuntimeError("x")

    with pytest.raises(RuntimeError) as raised:
        with context.external_effect():
            raise boom

    assert raised.value is boom


# --- The attestation rule -----------------------------------------------------------


def _attested(error: BaseException, block: BaseException | None) -> bool:
    return dispatch._is_attested_not_sent(error, block)  # pyright: ignore[reportPrivateUsage]


def test_a_confirmed_not_sent_that_left_the_block_is_an_attestation() -> None:
    error = _NotSent("refused")
    assert _attested(error, error) is True


def test_a_fresh_confirmed_not_sent_is_not_an_attestation() -> None:
    assert _attested(_NotSent("fresh"), _NotSent("block")) is False
    assert _attested(_NotSent("fresh"), RuntimeError("block")) is False


def test_without_a_block_exception_nothing_is_an_attestation() -> None:
    assert _attested(_NotSent("x"), None) is False


@pytest.mark.parametrize(
    "other",
    [
        TimeoutError("t"),
        RuntimeError("r"),
        _amb(),
        _amb(at_least_once=True),
        PermanentEventError("p"),
    ],
    ids=["timeout", "runtime", "ambiguous", "at_least_once", "permanent"],
)
def test_a_group_with_a_leaf_that_is_not_confirmed_is_not_an_attestation(
    other: Exception,
) -> None:
    confirmed = _NotSent("refused")
    group = ExceptionGroup("g", [confirmed, other])
    assert _attested(group, group) is False


def test_a_group_of_confirmed_leaves_from_the_block_is_an_attestation() -> None:
    first, second = _NotSent("a"), _NotSentTimeout("b")
    inner = ExceptionGroup("inner", [second])
    group = ExceptionGroup("g", [first, inner])
    assert _attested(group, group) is True


def test_a_group_the_consumer_rewraps_stays_an_attestation_by_its_leaves() -> None:
    first, second = _NotSent("a"), _NotSent("b")
    block = ExceptionGroup("block", [first, second])
    rewrapped = ExceptionGroup("outer", [first])
    assert _attested(rewrapped, block) is True


def test_a_group_with_a_leaf_that_did_not_come_from_the_block_is_not() -> None:
    first = _NotSent("a")
    block = ExceptionGroup("block", [first])
    mixed = ExceptionGroup("outer", [first, _NotSent("fresh")])
    assert _attested(mixed, block) is False


def test_an_attestation_that_is_also_a_timeout_is_still_one() -> None:
    error = _NotSentTimeout("pool timeout")
    assert _attested(error, error) is True


# --- The dispatcher's routing ----------------------------------------------------------


@dataclass
class _Recorder:
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
        return "pending"

    def record_confirmed(
        self,
        tenant_id: uuid.UUID,
        event_id: uuid.UUID,
        token: uuid.UUID,
        error: Any,
        **kwargs: Any,
    ) -> str:
        self.calls.append(("confirmed", error, kwargs))
        return "pending"

    @property
    def only(self) -> tuple[str, Any, dict[str, Any]]:
        (call,) = self.calls
        return call


@pytest.fixture
def recorder(monkeypatch: pytest.MonkeyPatch) -> _Recorder:
    rec = _Recorder()
    monkeypatch.setattr(outbox_dispatcher, "fail_event", rec.fail_event)
    monkeypatch.setattr(outbox_dispatcher, "record_ambiguous_outcome", rec.record_ambiguous)
    monkeypatch.setattr(outbox_dispatcher, "record_confirmed_not_sent", rec.record_confirmed)
    return rec


def _starter(*, started: bool, block: BaseException | None) -> Any:
    starter = outbox_dispatcher._ExternalEffectStarter(  # pyright: ignore[reportPrivateUsage]
        _TENANT, _EVENT, _TOKEN
    )
    starter.started = started
    starter.block_exception = block
    return starter


def _record(exc: Exception, *, started: bool = True, block: BaseException | None = None) -> None:
    outbox_dispatcher._record_consumer_failure(  # pyright: ignore[reportPrivateUsage]
        TenantJobContext(tenant_id=_TENANT),
        _EVENT,
        _TOKEN,
        exc,
        {},
        _starter(started=started, block=block if block is not None else exc),
    )


def test_a_marked_confirmed_not_sent_goes_to_the_verifying_function(recorder: _Recorder) -> None:
    error = _NotSent("refused")
    _record(error)
    kind, recorded, kwargs = recorder.only
    assert kind == "confirmed" and recorded is error
    assert kwargs == {"block_exception": error, "retry_after": None}


def test_the_dispatcher_hands_over_the_exception_not_a_verdict(recorder: _Recorder) -> None:
    """The function is told which exception left the block and judges for
    itself; the dispatcher never passes a boolean."""
    block = RuntimeError("inside")
    fresh = _NotSent("after")
    _record(fresh, block=block)
    _, recorded, kwargs = recorder.only
    assert recorded is fresh and kwargs["block_exception"] is block
    assert not any(isinstance(value, bool) for value in kwargs.values())


def test_an_attestation_that_is_also_a_retry_hint_keeps_both(recorder: _Recorder) -> None:
    """The attestation branch comes before the retry-hint branch."""
    _record(_NotSentRetryAfter())
    kind, _, kwargs = recorder.only
    assert kind == "confirmed" and kwargs["retry_after"] == 90


def test_a_group_of_confirmed_leaves_carries_no_hint(recorder: _Recorder) -> None:
    group = ExceptionGroup("g", [_NotSentRetryAfter(), _NotSent("b")])
    _record(group)
    kind, _, kwargs = recorder.only
    assert kind == "confirmed" and kwargs["retry_after"] is None


def test_a_combined_permanent_error_stays_terminal(recorder: _Recorder) -> None:
    _record(_NotSentPermanent("HTTP 410"))
    kind, _, kwargs = recorder.only
    assert (kind, kwargs) == ("fail_event", {"terminal": True})


@pytest.mark.parametrize(
    "exc",
    [
        ExceptionGroup("g", [_NotSent("a"), RuntimeError("b")]),
        ExceptionGroup("g", [_NotSent("a"), TimeoutError("b")]),
        RuntimeError("HTTP 503"),
        RetryAfterEventError(30, "Throttled"),
    ],
    ids=["group_runtime", "group_timeout", "plain", "retry_after_alone"],
)
def test_a_marked_failure_that_is_not_attested_keeps_the_old_path(
    recorder: _Recorder, exc: Exception
) -> None:
    _record(exc)
    kind, _, _ = recorder.only
    assert kind in {"fail_event", "ambiguous"}


def test_a_marked_group_mixing_confirmed_and_a_timeout_is_ambiguous(recorder: _Recorder) -> None:
    _record(ExceptionGroup("g", [_NotSent("a"), TimeoutError("b")]))
    assert recorder.only[0] == "ambiguous"


def test_with_markers_off_nothing_is_marked_and_the_new_branches_are_unreachable(
    recorder: _Recorder,
) -> None:
    for error in (_NotSent("refused"), _NotSentRetryAfter(), _NotSentTimeout("pool")):
        recorder.calls.clear()
        _record(error, started=False)
        assert recorder.only[0] == "fail_event"
    recorder.calls.clear()
    outbox_dispatcher._record_consumer_failure(  # pyright: ignore[reportPrivateUsage]
        TenantJobContext(tenant_id=_TENANT), _EVENT, _TOKEN, _NotSent("x"), {}
    )
    assert recorder.only[0] == "fail_event"  # no starter at all: the old signature


def test_a_marked_at_least_once_that_the_consumer_raised_is_honoured(
    recorder: _Recorder,
) -> None:
    _record(_amb(at_least_once=True))
    kind, recorded, _ = recorder.only
    assert kind == "ambiguous" and recorded.at_least_once is True


def test_a_marked_at_least_once_group_of_declarations_is_honoured(recorder: _Recorder) -> None:
    _record(ExceptionGroup("g", [_amb(at_least_once=True), _amb(at_least_once=True)]))
    assert recorder.only[2] == {} and recorder.only[1].at_least_once is True


@pytest.mark.parametrize(
    "exc",
    [
        ExceptionGroup("g", [_amb(at_least_once=True), _amb()]),
        ExceptionGroup("g", [_amb(at_least_once=True), _amb(retry_within=timedelta(hours=1))]),
        ExceptionGroup("g", [_amb(at_least_once=True), RuntimeError("other")]),
        ExceptionGroup("g", [_amb(at_least_once=True), _NotSent("a")]),
        ExceptionGroup("g", [_amb(at_least_once=True), TimeoutError("t")]),
    ],
    ids=[
        "no_policy_member",
        "retry_within_member",
        "runtime_member",
        "confirmed_member",
        "timeout",
    ],
)
def test_a_marked_mixed_group_is_not_honoured_as_at_least_once(
    recorder: _Recorder, exc: Exception
) -> None:
    _record(exc)
    kind, recorded, _ = recorder.only
    assert kind == "ambiguous" and recorded.at_least_once is False
    assert recorded.retry_within is None


def test_an_unmarked_mixed_group_keeps_todays_policy(recorder: _Recorder) -> None:
    """With nothing marked the group rule of #197 is unchanged: the
    ambiguous members decide."""
    _record(ExceptionGroup("g", [_amb(at_least_once=True), RuntimeError("other")]), started=False)
    assert recorder.only[1].at_least_once is True


def test_a_marked_retry_within_stays_dead_lettered_through_its_own_policy(
    recorder: _Recorder,
) -> None:
    """The dispatcher passes `retry_within` on; the state machine, which
    checks the marker under the lock, refuses it (integration tests)."""
    _record(_amb(retry_within=timedelta(hours=1)))
    kind, recorded, _ = recorder.only
    assert kind == "ambiguous" and recorded.retry_within == timedelta(hours=1)


def test_the_webhook_classes_are_what_the_design_expects() -> None:
    sent = WebhookNotSentError(uuid.uuid4(), "connect_failed")
    ambiguous = WebhookAmbiguousDeliveryError(uuid.uuid4(), "read_timeout", phase="read")
    assert isinstance(sent, ConfirmedNotSentError)
    assert isinstance(ambiguous, AmbiguousOutcomeError) and ambiguous.at_least_once is True


# --- Logs ------------------------------------------------------------------------------


def test_the_marker_log_field_exists_only_for_a_marked_attempt() -> None:
    fields = outbox_dispatcher._marker_log_fields  # pyright: ignore[reportPrivateUsage]
    assert fields("pending", False) == {}
    assert fields("dead_lettered", False) == {}
    assert fields("pending", True) == {"outbox_started_marker": "cleared"}
    assert fields("dead_lettered", True) == {"outbox_started_marker": "kept"}
    assert fields(None, True) == {"outbox_started_marker": "kept"}


def test_the_retry_logs_carry_no_url_and_no_message(
    recorder: _Recorder, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level("INFO")
    _record(_NotSent(_CANARY))
    text = " ".join(
        f"{record.getMessage()} {sorted(record.__dict__.items())}" for record in caplog.records
    )
    assert _CANARY not in text
    assert "outbox_started_marker" in text
