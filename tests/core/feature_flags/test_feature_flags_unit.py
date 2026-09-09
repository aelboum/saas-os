"""Pure unit tests for `core/feature_flags/service.py` -- no database
needed. Key validation raises before any database access is attempted
(`_validate_key()` runs synchronously ahead of `session_scope()`), and
`evaluate_flag()`'s read-failure fallback is exercised here by simulating
a database read failure via monkeypatching, not a real outage -- the
behavior under a *real* failure is out of scope for a unit test and isn't
claimed to be proven here.
"""

from __future__ import annotations

import uuid

import pytest
from core.feature_flags.errors import InvalidFeatureFlagKeyError

from core.feature_flags import service as feature_flags_service
from infra.db import OperationalError


def test_create_flag_rejects_empty_key() -> None:
    with pytest.raises(InvalidFeatureFlagKeyError):
        feature_flags_service.create_flag("")


def test_create_flag_rejects_whitespace_only_key() -> None:
    with pytest.raises(InvalidFeatureFlagKeyError):
        feature_flags_service.create_flag("   ")


def test_create_flag_rejects_overlong_key() -> None:
    with pytest.raises(InvalidFeatureFlagKeyError):
        feature_flags_service.create_flag("x" * 151)


def test_evaluate_flag_returns_default_on_database_read_failure(monkeypatch) -> None:
    """docs/IMPLEMENTATION-ROADMAP.md Phase 4.2 Rollback Strategy: "flags
    default to a documented safe default on read failure" -- simulated
    here via a monkeypatched session_scope that raises OperationalError,
    the same exception class a real connectivity failure would raise
    (infra.db.OperationalError, re-exported from sqlalchemy.exc).
    """

    def _raise_operational_error(*args: object, **kwargs: object) -> None:
        raise OperationalError("simulated connectivity failure", None, Exception("simulated"))

    monkeypatch.setattr(feature_flags_service, "session_scope", _raise_operational_error)

    assert feature_flags_service.evaluate_flag(uuid.uuid4(), "any-key", default=True) is True
    assert feature_flags_service.evaluate_flag(uuid.uuid4(), "any-key", default=False) is False


def test_evaluate_flag_default_parameter_defaults_to_false(monkeypatch) -> None:
    def _raise_operational_error(*args: object, **kwargs: object) -> None:
        raise OperationalError("simulated connectivity failure", None, Exception("simulated"))

    monkeypatch.setattr(feature_flags_service, "session_scope", _raise_operational_error)

    assert feature_flags_service.evaluate_flag(uuid.uuid4(), "any-key") is False
