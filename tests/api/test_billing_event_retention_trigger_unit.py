"""ADR-0048 -- `python -m saas_os.api.billing_event_retention_trigger`
enqueues exactly one retention job and exits, failing closed (a non-zero
exit, the error logged by type) when it cannot."""

from __future__ import annotations

import pytest

from saas_os.api import billing_event_retention_trigger as trigger
from saas_os.core.billing.provider_event_jobs import BILLING_EVENT_RETENTION_JOB_NAME
from saas_os.infra.jobs import JobsConfigurationError


@pytest.fixture(autouse=True)
def _no_logging_reconfiguration(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(trigger, "configure_logging", lambda: None)


def test_it_enqueues_the_retention_job_with_no_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, object]] = []

    async def fake_enqueue(name: str, *, payload: object) -> str:
        calls.append((name, payload))
        return "job-1"

    monkeypatch.setattr(trigger, "enqueue_job", fake_enqueue)
    assert trigger.main([]) == 0
    assert calls == [(BILLING_EVENT_RETENTION_JOB_NAME, None)]
    assert BILLING_EVENT_RETENTION_JOB_NAME == "_prune_billing_provider_events_job"


def test_a_queue_failure_exits_non_zero(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    async def failing(name: str, *, payload: object) -> str:
        raise JobsConfigurationError("REDIS_URL is not set.")

    monkeypatch.setattr(trigger, "enqueue_job", failing)
    assert trigger.main([]) == 1
    assert "billing_event_retention_trigger_failed" in caplog.text


def test_arguments_are_refused() -> None:
    assert trigger.main(["--now"]) == 1
