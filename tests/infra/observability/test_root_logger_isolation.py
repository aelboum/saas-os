"""RA-11-F7 regression: the repository root `conftest.py`'s autouse
`_restore_root_logger_state` fixture must stop `configure_logging()`'s
process-global `logging.basicConfig(force=True)` from leaking past the
test that called it -- both the mutated root level/handler set, and (the
concrete reproduced failure) a JSON `StreamHandler` left bound to a
`capsys`-owned stream that gets closed at that test's own teardown.
"""

from __future__ import annotations

import logging

import pytest

from saas_os.infra.observability.config import ObservabilityConfig
from saas_os.infra.observability.logging import configure_logging


@pytest.fixture(scope="module")
def _root_logger_baseline() -> tuple[int, list[logging.Handler]]:
    """Captured once, before the first test in this module runs. By that
    point the root `conftest.py`'s autouse fixture has already restored
    the root logger to pytest's own steady state after every earlier
    test in the session, so this is the "clean" baseline the tests below
    compare against directly -- not an assumed hardcoded level or
    handler set."""
    root = logging.getLogger()
    return root.level, root.handlers[:]


def test_configure_logging_mutates_the_root_logger_for_the_test_that_calls_it(
    _root_logger_baseline: tuple[int, list[logging.Handler]],
) -> None:
    """Reproduces the audited mutation directly: `configure_logging()`
    really does change the root level and handler set. Proves the next
    test's restored state (below) is a genuine fixture effect, not a
    no-op because nothing changed in the first place."""
    baseline_level, baseline_handlers = _root_logger_baseline
    configure_logging(ObservabilityConfig(log_level="INFO"))

    root = logging.getLogger()
    assert root.level == logging.INFO
    assert root.handlers != baseline_handlers
    assert any(isinstance(h, logging.StreamHandler) for h in root.handlers)


def test_root_logger_state_is_restored_after_the_previous_test(
    _root_logger_baseline: tuple[int, list[logging.Handler]],
) -> None:
    """RA-11-F7: after the previous test's `configure_logging()` call and
    that test's own teardown, the root logger must be back to exactly
    the state captured in the baseline -- proven directly against that
    captured baseline, not merely "this test happens to pass"."""
    baseline_level, baseline_handlers = _root_logger_baseline
    root = logging.getLogger()
    assert root.level == baseline_level
    assert root.handlers == baseline_handlers
    assert not any(h not in baseline_handlers for h in root.handlers)


def test_configure_logging_under_capsys_does_not_leak_a_closed_stream_handler(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Reproduces the exact audited failure mechanism: `configure_logging()`
    binds its `StreamHandler` to `sys.stdout` as `capsys` has replaced it
    for THIS test; that buffer is closed at this test's own teardown.
    Without the root `conftest.py` fixture, the handler stays on the root
    logger and the very next test to emit an INFO+ record produces
    `ValueError: I/O operation on closed file` (audited: 168 such blocks
    across the default suite run with `-s`). This test only sets the
    trap -- the next test proves it was defused."""
    configure_logging(ObservabilityConfig(log_level="INFO"))
    logging.getLogger("f7.capsys-trap").info("about to leave this test")


def test_a_later_test_can_log_after_the_capsys_trap_without_a_closed_stream_error(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """If the previous test's `StreamHandler` (bound to its now-closed
    `capsys` buffer) were still attached to the root logger, this
    `logger.info()` call would trigger `StreamHandler.emit()`'s own
    except-clause -> `handleError()` -> a `--- Logging error ---` /
    `ValueError: I/O operation on closed file` block printed to stderr
    (never raised -- `logging.Handler.handleError()`'s own default
    behavior, exactly why the audited flood never changed a single
    test's pass/fail outcome, only polluted stderr). It does not happen
    here, because the root `conftest.py` fixture removed that handler
    when the previous test finished."""
    capsys.readouterr()  # discard anything already buffered
    logging.getLogger("f7.after-capsys-trap").info("no closed-stream error here")
    captured = capsys.readouterr()
    assert "Logging error" not in captured.err
    assert "I/O operation on closed file" not in captured.err
