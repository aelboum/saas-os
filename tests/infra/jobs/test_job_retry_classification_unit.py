"""The job wrapper's retry decision for errors that reach it unclassified
(ledger rows of 2026-11-02 in docs/P-ROADMAP.md, second review of #197):

- an `AmbiguousOutcomeError` inside an exception group is not retried (a
  group was retried before: the wrapper looked at the raised error only);
- `EmailOutcomeUnknownError` escaping a product's own job is not retried,
  with or without a provider de-duplication window (a direct job cannot
  honour the window, as for `AmbiguousOutcomeError`);
- `PermanentEventError` (and any `PermanentJobError`) is dead-lettered on
  its first attempt; a group is, when every error in it is permanent.

Each case runs through both wrappers (system and tenant jobs). Unit level:
the wrapper is called directly against a fake Redis pool.
"""

from __future__ import annotations

from datetime import timedelta
from typing import TYPE_CHECKING

import pytest
from arq import Retry

from saas_os.core.email.errors import (
    EmailNotSentError,
    EmailOutcomeUnknownError,
    EmailProviderError,
)
from saas_os.core.outbox import AmbiguousOutcomeError, PermanentEventError
from saas_os.infra.jobs.config import JobsConfig
from saas_os.infra.jobs.context import JobKind
from saas_os.infra.jobs.errors import (
    JobDeadLetteredError,
    NonRetriableJobError,
    PermanentJobError,
)
from saas_os.infra.jobs.queue import (
    TenantJobPayload,
    _with_retry_and_dead_letter,  # pyright: ignore[reportPrivateUsage]
)

if TYPE_CHECKING:
    from tests.infra.jobs.conftest import FakeRedisPool

pytestmark = pytest.mark.anyio

_CONFIG = JobsConfig(
    redis_url="redis://localhost:6379/0", max_tries=3, retry_backoff_base_seconds=1.0
)
_TENANT = "00000000-0000-0000-0000-0000000000a7"


@pytest.fixture
def dead_letters(monkeypatch: pytest.MonkeyPatch, fake_redis_pool: FakeRedisPool) -> FakeRedisPool:
    async def _fake_get_redis_pool(config: object = None) -> FakeRedisPool:
        return fake_redis_pool

    monkeypatch.setattr("saas_os.infra.jobs.queue.get_redis_pool", _fake_get_redis_pool)
    return fake_redis_pool


@pytest.fixture(params=[JobKind.SYSTEM, JobKind.TENANT], ids=["system", "tenant"])
def kind(request: pytest.FixtureRequest) -> JobKind:
    return request.param


async def _run(kind: JobKind, error: BaseException) -> tuple[type[BaseException], int]:
    """Runs a handler that raises `error` on its first attempt (attempts
    remain). Returns what the wrapper raised and how often the handler ran."""
    calls: list[int] = []

    async def handler(*_args: object) -> None:
        calls.append(1)
        raise error

    wrapped = _with_retry_and_dead_letter(handler, config=_CONFIG, kind=kind)
    payload = TenantJobPayload(tenant_id=_TENANT) if kind is JobKind.TENANT else None
    with pytest.raises((Retry, JobDeadLetteredError)) as excinfo:
        await wrapped({"job_try": 1, "job_id": "job-1"}, payload)
    return excinfo.type, len(calls)


def _ambiguous() -> AmbiguousOutcomeError:
    return AmbiguousOutcomeError("data_lost", phase="data")


def _permanent() -> PermanentEventError:
    return PermanentEventError("malformed event")


# --- exception groups ---------------------------------------------------------


@pytest.mark.parametrize(
    "error",
    [
        ExceptionGroup("sends", [_ambiguous()]),
        ExceptionGroup("sends", [RuntimeError("transient"), _ambiguous()]),
        ExceptionGroup("outer", [ExceptionGroup("inner", [_ambiguous()])]),
    ],
    ids=["alone", "beside-a-transient-error", "nested"],
)
async def test_an_ambiguous_outcome_inside_a_group_is_not_retried(
    dead_letters: FakeRedisPool, kind: JobKind, error: BaseException
) -> None:
    raised, calls = await _run(kind, error)
    assert raised is JobDeadLetteredError
    assert calls == 1
    assert len(dead_letters.lists[_CONFIG.dead_letter_key]) == 1


async def test_a_group_whose_ambiguous_outcome_is_retry_safe_keeps_the_retry(
    dead_letters: FakeRedisPool, kind: JobKind
) -> None:
    safe = AmbiguousOutcomeError("read_timeout", phase="read", at_least_once=True)
    raised, _ = await _run(kind, ExceptionGroup("sends", [safe]))
    assert raised is Retry


async def test_a_group_of_transient_errors_keeps_the_retry(
    dead_letters: FakeRedisPool, kind: JobKind
) -> None:
    raised, _ = await _run(kind, ExceptionGroup("calls", [RuntimeError("a"), OSError("b")]))
    assert raised is Retry
    assert dead_letters.lists.get(_CONFIG.dead_letter_key, []) == []


# --- an e-mail whose outcome is unknown ----------------------------------------


@pytest.mark.parametrize(
    "error",
    [
        EmailOutcomeUnknownError("send", "SMTPServerDisconnected", phase="data"),
        EmailOutcomeUnknownError(
            "send", "ReadTimeout", phase="read", retry_within=timedelta(hours=24)
        ),
    ],
    ids=["no-window", "provider-window"],
)
async def test_an_email_whose_outcome_is_unknown_is_not_sent_again_by_the_job(
    dead_letters: FakeRedisPool, kind: JobKind, error: EmailOutcomeUnknownError
) -> None:
    assert isinstance(error, NonRetriableJobError)
    assert isinstance(error, EmailProviderError)  # existing handlers still catch it
    raised, calls = await _run(kind, error)
    assert raised is JobDeadLetteredError
    assert calls == 1


async def test_an_email_that_was_not_sent_keeps_the_retry(
    dead_letters: FakeRedisPool, kind: JobKind
) -> None:
    raised, _ = await _run(kind, EmailNotSentError("send", "ConnectionRefusedError"))
    assert raised is Retry


# --- permanent errors ----------------------------------------------------------


@pytest.mark.parametrize(
    "error",
    [
        _permanent(),
        ExceptionGroup("events", [_permanent(), _permanent()]),
    ],
    ids=["alone", "a-group-of-permanent-errors"],
)
async def test_a_permanent_error_is_dead_lettered_on_its_first_attempt(
    dead_letters: FakeRedisPool, kind: JobKind, error: BaseException
) -> None:
    raised, calls = await _run(kind, error)
    assert raised is JobDeadLetteredError
    assert calls == 1
    assert len(dead_letters.lists[_CONFIG.dead_letter_key]) == 1


async def test_a_group_with_one_transient_error_beside_a_permanent_one_keeps_the_retry(
    dead_letters: FakeRedisPool, kind: JobKind
) -> None:
    """The transient part may succeed next time; a retry repeats nothing."""
    raised, _ = await _run(kind, ExceptionGroup("events", [_permanent(), RuntimeError("t")]))
    assert raised is Retry


def test_the_outbox_permanent_errors_carry_the_job_marker() -> None:
    from saas_os.core.notifications.errors import NotificationPermanentDispatchError
    from saas_os.core.usage.errors import MalformedUsageEventError
    from saas_os.core.webhooks.errors import (
        MalformedWebhookEventError,
        WebhookDestinationRejectedError,
        WebhookPermanentDeliveryError,
    )

    for error_type in (
        PermanentEventError,
        NotificationPermanentDispatchError,
        MalformedUsageEventError,
        MalformedWebhookEventError,
        WebhookDestinationRejectedError,
        WebhookPermanentDeliveryError,
    ):
        assert issubclass(error_type, PermanentJobError), error_type
