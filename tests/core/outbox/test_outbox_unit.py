"""`core.outbox.append_event()` input validation (RE-1, transactional outbox).

A malformed event is rejected before the caller's session is touched at
all: nothing is added, nothing is flushed. No database needed.
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from core.outbox import InvalidOutboxEventError, append_event


class _UntouchableSession:
    """Fails the test if `append_event()` uses the session at all."""

    def __getattr__(self, name: str) -> Any:
        raise AssertionError(f"session.{name} used for an invalid event")


def _call(**overrides: object) -> None:
    kwargs: dict[str, Any] = {
        "tenant_id": uuid.uuid4(),
        "event_type": "webhook.delivery",
        "aggregate_type": "webhook_subscription",
        "aggregate_id": str(uuid.uuid4()),
        "payload": {"k": "v"},
    }
    kwargs.update(overrides)
    append_event(_UntouchableSession(), **kwargs)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("tenant_id", "not-a-uuid"),
        ("tenant_id", None),
        ("event_type", ""),
        ("event_type", "nodot"),
        ("event_type", "Upper.Case"),
        ("event_type", "a." + "b" * 100),
        ("event_type", 7),
        ("aggregate_type", ""),
        ("aggregate_type", "with.dot"),
        ("aggregate_type", "Upper"),
        ("aggregate_id", ""),
        ("aggregate_id", "x" * 256),
        ("aggregate_id", uuid.uuid4()),
        ("payload", None),
        ("payload", ["not", "an", "object"]),
        ("payload", {"when": object()}),
        ("payload", {"nan": float("nan")}),
        ("payload", {1: "non-string key"}),
        ("payload", {"t": (1, 2)}),
    ],
)
def test_malformed_event_is_rejected_before_the_session_is_used(field: str, value: object) -> None:
    with pytest.raises(InvalidOutboxEventError) as excinfo:
        _call(**{field: value})
    assert excinfo.value.field == field


def test_error_never_echoes_the_payload() -> None:
    with pytest.raises(InvalidOutboxEventError) as excinfo:
        _call(payload={"secret-ish": object()})
    assert "secret-ish" not in str(excinfo.value)


def test_append_event_requires_a_session_and_keyword_arguments() -> None:
    untyped: Any = append_event  # the call under test is deliberately invalid
    with pytest.raises(TypeError):
        untyped(uuid.uuid4(), "webhook.delivery", "agg", "id", {})
